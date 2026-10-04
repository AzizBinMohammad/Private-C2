package middleware

import (
	"context"
	"crypto/tls"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	OperatorIDKey   contextKey = "operator_id"
	OperatorNameKey contextKey = "operator_name"
	OperatorRoleKey contextKey = "operator_role"
	SourceIPKey     contextKey = "source_ip"
)

type OperatorInfo struct {
	ID   string
	Name string
	Role string
}

type OperatorLookup func(ctx context.Context, commonName string) (*OperatorInfo, error)

func AuthUnaryInterceptor(lookup OperatorLookup) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		newCtx, err := authenticateFromTLS(ctx, lookup)
		if err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

func AuthStreamInterceptor(lookup OperatorLookup) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx, err := authenticateFromTLS(ss.Context(), lookup)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: newCtx})
	}
}

func authenticateFromTLS(ctx context.Context, lookup OperatorLookup) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no TLS credentials")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return nil, status.Error(codes.Unauthenticated, "no verified certificate chain")
	}

	leaf := tlsInfo.State.VerifiedChains[0][0]
	cn := leaf.Subject.CommonName
	if cn == "" {
		return nil, status.Error(codes.Unauthenticated, "empty common name")
	}

	op, err := lookup(ctx, cn)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "operator not found")
	}

	ctx = context.WithValue(ctx, OperatorIDKey, op.ID)
	ctx = context.WithValue(ctx, OperatorNameKey, op.Name)
	ctx = context.WithValue(ctx, OperatorRoleKey, op.Role)

	addr := p.Addr.String()
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		addr = addr[:idx]
	}
	ctx = context.WithValue(ctx, SourceIPKey, addr)

	return ctx, nil
}

func GetOperatorID(ctx context.Context) string {
	v, _ := ctx.Value(OperatorIDKey).(string)
	return v
}

func GetOperatorRole(ctx context.Context) string {
	v, _ := ctx.Value(OperatorRoleKey).(string)
	return v
}

func GetSourceIP(ctx context.Context) string {
	v, _ := ctx.Value(SourceIPKey).(string)
	return v
}

func GetTLSState(ctx context.Context) (*tls.ConnectionState, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, false
	}
	return &tlsInfo.State, true
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
