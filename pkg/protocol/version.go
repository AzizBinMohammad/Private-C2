package protocol

// Protocol versions are additive. A peer that omits protocol_version is a v1
// peer; v2 peers negotiate min(client, server) and only use v2 message types
// after the register_ack advertises the negotiated version.
const (
	Version1       = 1
	Version2       = 2
	CurrentVersion = Version2
)

// Capability names advertised during registration.
const (
	CapabilityTaskStarted  = "task_started"
	CapabilityKill         = "kill"
	CapabilitySessionToken = "session_token"
)

// Negotiate returns the highest mutually supported protocol version. Missing
// or invalid client versions are treated as v1 for backward compatibility.
func Negotiate(client int) int {
	if client <= 0 {
		return Version1
	}
	if client < CurrentVersion {
		return client
	}
	return CurrentVersion
}

// HasCapability reports whether capability is present in a capability list.
func HasCapability(capabilities []string, capability string) bool {
	for _, c := range capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
