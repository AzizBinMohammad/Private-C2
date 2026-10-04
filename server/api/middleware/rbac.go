package middleware

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Permission string

const (
	PermSessionRead   Permission = "session.read"
	PermSessionWrite  Permission = "session.write"
	PermBeaconRead    Permission = "beacon.read"
	PermBeaconWrite   Permission = "beacon.write"
	PermListenerRead  Permission = "listener.read"
	PermListenerWrite Permission = "listener.write"
	PermPayloadBuild  Permission = "payload.build"
	PermTaskExecute   Permission = "task.execute"
	PermEngagementManage Permission = "engagement.manage"
	PermAuditRead     Permission = "audit.read"
	PermAdminManage   Permission = "admin.manage"
)

var rolePermissions = map[string][]Permission{
	"admin": {
		PermSessionRead, PermSessionWrite,
		PermBeaconRead, PermBeaconWrite,
		PermListenerRead, PermListenerWrite,
		PermPayloadBuild, PermTaskExecute,
		PermEngagementManage, PermAuditRead,
		PermAdminManage,
	},
	"operator": {
		PermSessionRead, PermSessionWrite,
		PermBeaconRead, PermBeaconWrite,
		PermListenerRead, PermListenerWrite,
		PermPayloadBuild, PermTaskExecute,
		PermAuditRead,
	},
	"builder": {
		PermPayloadBuild,
		PermSessionRead, PermBeaconRead,
		PermListenerRead,
	},
	"observer": {
		PermSessionRead, PermBeaconRead,
		PermListenerRead, PermAuditRead,
	},
}

var methodPermissions = map[string]Permission{
	"/privatec2.v1.OperatorService/ListSessions":    PermSessionRead,
	"/privatec2.v1.OperatorService/GetSession":       PermSessionRead,
	"/privatec2.v1.OperatorService/InteractSession":  PermSessionWrite,
	"/privatec2.v1.OperatorService/ListBeacons":      PermBeaconRead,
	"/privatec2.v1.OperatorService/GetBeacon":        PermBeaconRead,
	"/privatec2.v1.OperatorService/ListListeners":    PermListenerRead,
	"/privatec2.v1.OperatorService/StartListener":    PermListenerWrite,
	"/privatec2.v1.OperatorService/StopListener":     PermListenerWrite,
	"/privatec2.v1.OperatorService/GeneratePayload":  PermPayloadBuild,
	"/privatec2.v1.OperatorService/SubmitTask":       PermTaskExecute,
	"/privatec2.v1.OperatorService/GetTaskResult":    PermTaskExecute,
	"/privatec2.v1.OperatorService/UploadFile":       PermTaskExecute,
	"/privatec2.v1.OperatorService/DownloadFile":     PermTaskExecute,
	"/privatec2.v1.OperatorService/ListProcesses":    PermSessionRead,
	"/privatec2.v1.EngagementService/CreateEngagement": PermEngagementManage,
	"/privatec2.v1.EngagementService/GetEngagement":    PermEngagementManage,
	"/privatec2.v1.EngagementService/ListEngagements":  PermEngagementManage,
	"/privatec2.v1.EngagementService/UpdateEngagement": PermEngagementManage,
	"/privatec2.v1.EngagementService/CheckScope":       PermSessionRead,
	"/privatec2.v1.EngagementService/ActivateKillSwitch": PermEngagementManage,
	"/privatec2.v1.AuditService/QueryAuditLog":  PermAuditRead,
	"/privatec2.v1.AuditService/ExportAuditLog": PermAuditRead,
	"/privatec2.v1.AuditService/VerifyChain":    PermAuditRead,
	"/privatec2.v1.AdminService/AddOperator":     PermAdminManage,
	"/privatec2.v1.AdminService/RemoveOperator":  PermAdminManage,
	"/privatec2.v1.AdminService/ListOperators":   PermAdminManage,
	"/privatec2.v1.AdminService/ServerStatus":    PermSessionRead,
}

func RBACUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := checkPermission(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func RBACStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := checkPermission(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func checkPermission(ctx context.Context, method string) error {
	requiredPerm, ok := methodPermissions[method]
	if !ok {
		return nil
	}

	role := GetOperatorRole(ctx)
	if role == "" {
		return status.Error(codes.PermissionDenied, "no role assigned")
	}

	perms, ok := rolePermissions[role]
	if !ok {
		return status.Error(codes.PermissionDenied, "unknown role")
	}

	for _, p := range perms {
		if p == requiredPerm {
			return nil
		}
	}

	return status.Errorf(codes.PermissionDenied, "role %q lacks %s permission", role, requiredPerm)
}

func HasPermission(role string, perm Permission) bool {
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == perm {
			return true
		}
	}
	return false
}
