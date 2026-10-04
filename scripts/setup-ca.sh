#!/bin/bash
#
# setup-ca.sh -- Generate a Private-C2 Certificate Authority and a
# server certificate signed by that CA.
#
# Usage:
#   ./scripts/setup-ca.sh [output-directory]
#
# The output directory defaults to ./certs.  Existing files will NOT be
# overwritten.
#
set -euo pipefail

OUT_DIR="${1:-certs}"
CA_DAYS=3650         # ~10 years
SERVER_DAYS=365      # 1 year
KEY_BITS=4096
CA_SUBJECT="/CN=Private-C2 Root CA/O=Private-C2/OU=Security Operations"
SERVER_CN="private-c2-server"

# ---- helpers ----
info()  { echo "[*] $*"; }
warn()  { echo "[!] $*" >&2; }
fatal() { echo "[!!] $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fatal "openssl is required but not found in PATH"

mkdir -p "${OUT_DIR}"

# ---- CA key + self-signed cert ----
CA_KEY="${OUT_DIR}/ca-key.pem"
CA_CERT="${OUT_DIR}/ca-cert.pem"

if [[ -f "${CA_KEY}" || -f "${CA_CERT}" ]]; then
    warn "CA files already exist in ${OUT_DIR}, skipping CA generation"
else
    info "Generating CA private key (${KEY_BITS}-bit RSA)"
    openssl genrsa -out "${CA_KEY}" "${KEY_BITS}" 2>/dev/null

    info "Creating self-signed CA certificate (valid ${CA_DAYS} days)"
    openssl req -new -x509 \
        -key "${CA_KEY}" \
        -out "${CA_CERT}" \
        -days "${CA_DAYS}" \
        -subj "${CA_SUBJECT}" \
        -sha256

    chmod 600 "${CA_KEY}"
    chmod 644 "${CA_CERT}"
    info "CA certificate : ${CA_CERT}"
    info "CA private key : ${CA_KEY}"
fi

# ---- Server certificate ----
SERVER_KEY="${OUT_DIR}/server-key.pem"
SERVER_CSR="${OUT_DIR}/server.csr"
SERVER_CERT="${OUT_DIR}/server-cert.pem"
SERVER_EXT="${OUT_DIR}/server-ext.cnf"

if [[ -f "${SERVER_KEY}" || -f "${SERVER_CERT}" ]]; then
    warn "Server cert files already exist in ${OUT_DIR}, skipping server cert generation"
else
    info "Generating server private key (${KEY_BITS}-bit RSA)"
    openssl genrsa -out "${SERVER_KEY}" "${KEY_BITS}" 2>/dev/null

    info "Creating server CSR"
    openssl req -new \
        -key "${SERVER_KEY}" \
        -out "${SERVER_CSR}" \
        -subj "/CN=${SERVER_CN}/O=Private-C2"

    # Extension file for SAN (Subject Alternative Names).
    cat > "${SERVER_EXT}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=@alt_names

[alt_names]
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
EOF

    info "Signing server certificate with CA (valid ${SERVER_DAYS} days)"
    openssl x509 -req \
        -in "${SERVER_CSR}" \
        -CA "${CA_CERT}" \
        -CAkey "${CA_KEY}" \
        -CAcreateserial \
        -out "${SERVER_CERT}" \
        -days "${SERVER_DAYS}" \
        -sha256 \
        -extfile "${SERVER_EXT}"

    chmod 600 "${SERVER_KEY}"
    chmod 644 "${SERVER_CERT}"

    # Clean up intermediary files.
    rm -f "${SERVER_CSR}" "${SERVER_EXT}" "${OUT_DIR}/ca-cert.srl"

    info "Server certificate : ${SERVER_CERT}"
    info "Server private key : ${SERVER_KEY}"
fi

# ---- Print summary ----
echo ""
echo "============================================="
echo "  CA and server certificates are ready"
echo "  Output directory: ${OUT_DIR}"
echo "============================================="
echo ""
echo "Files:"
ls -la "${OUT_DIR}"/*.pem 2>/dev/null || true
echo ""
echo "Environment variables for the server:"
echo "  export PC2_CA_CERT_PATH=${CA_CERT}"
echo "  export PC2_SERVER_CERT_PATH=${SERVER_CERT}"
echo "  export PC2_SERVER_KEY_PATH=${SERVER_KEY}"
echo ""
echo "Next: run ./scripts/add-operator.sh <operator-name> to generate"
echo "      an operator client certificate."
