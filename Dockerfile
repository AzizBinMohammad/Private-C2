# ---------- builder stage ----------
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Copy go.work and all module definitions first for layer caching.
COPY go.work ./
COPY pkg/go.mod pkg/go.sum* ./pkg/
COPY server/go.mod server/go.sum ./server/
COPY client/go.mod client/go.sum* ./client/
COPY cmd/server/go.mod cmd/server/go.sum ./cmd/server/
COPY cmd/client/go.mod cmd/client/go.sum* ./cmd/client/
COPY cmd/builder/go.mod cmd/builder/go.sum* ./cmd/builder/
COPY implant/go.mod implant/go.sum* ./implant/

RUN go work sync && \
    cd cmd/server && go mod download

# Copy all source code.
COPY . .

# Build the server binary — static, no CGO (uses pure-Go SQLite driver
# when CGO_ENABLED=0 is acceptable, otherwise switch to CGO_ENABLED=1
# and install build-base in the apk add line above).
RUN CGO_ENABLED=1 \
    GOOS=linux \
    go build -trimpath -ldflags="-s -w" \
    -o /out/private-c2-server ./cmd/server

# ---------- runtime stage ----------
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S pc2 && adduser -S pc2 -G pc2

COPY --from=builder /out/private-c2-server /usr/local/bin/private-c2-server

# Default directories for certificates, database, and audit logs.
RUN mkdir -p /etc/private-c2/certs /var/lib/private-c2 /var/log/private-c2 && \
    chown -R pc2:pc2 /etc/private-c2 /var/lib/private-c2 /var/log/private-c2

USER pc2

# gRPC
EXPOSE 31337
# Metrics / health
EXPOSE 9090

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- http://localhost:9090/healthz || exit 1

ENTRYPOINT ["private-c2-server"]
