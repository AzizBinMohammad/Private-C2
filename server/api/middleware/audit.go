package middleware

import (
	"context"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
)

type AuditLogger interface {
	Log(ctx context.Context, entry AuditLogEntry)
}

type AuditLogEntry struct {
	ID            string
	Timestamp     time.Time
	OperatorID    string
	SourceIP      string
	Method        string
	EngagementID  string
	CorrelationID string
	Duration      time.Duration
	Error         string
}

func AuditUnaryInterceptor(logger AuditLogger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		correlationID := uuid.New().String()

		resp, err := handler(ctx, req)

		entry := AuditLogEntry{
			ID:            uuid.New().String(),
			Timestamp:     start,
			OperatorID:    GetOperatorID(ctx),
			SourceIP:      GetSourceIP(ctx),
			Method:        info.FullMethod,
			CorrelationID: correlationID,
			Duration:      time.Since(start),
		}
		if err != nil {
			entry.Error = err.Error()
		}

		logger.Log(ctx, entry)
		return resp, err
	}
}

func AuditStreamInterceptor(logger AuditLogger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		correlationID := uuid.New().String()

		err := handler(srv, ss)

		entry := AuditLogEntry{
			ID:            uuid.New().String(),
			Timestamp:     start,
			OperatorID:    GetOperatorID(ss.Context()),
			SourceIP:      GetSourceIP(ss.Context()),
			Method:        info.FullMethod,
			CorrelationID: correlationID,
			Duration:      time.Since(start),
		}
		if err != nil {
			entry.Error = err.Error()
		}

		logger.Log(ss.Context(), entry)
		return err
	}
}
