package runtime

import "time"

// Config holds all implant runtime configuration.
type Config struct {
	// ServerURLs is the ordered list of C2 server endpoints to connect to.
	ServerURLs []string

	// ImplantID is the unique identifier assigned to this implant.
	ImplantID string

	// Mode is the operating mode: "session" for persistent connection,
	// "beacon" for interval-based check-in.
	Mode string

	// SleepInterval is the base interval between beacon check-ins.
	SleepInterval time.Duration

	// Jitter is the randomization factor applied to SleepInterval (0.0 to 1.0).
	// A value of 0.3 means the actual sleep will vary by +/- 30%.
	Jitter float64

	// KillDate is the date after which the implant self-terminates.
	// If nil, no kill date is enforced.
	KillDate *time.Time

	// KillSwitchURL is the remote URL checked each cycle. If unreachable
	// or non-200, the implant self-terminates (fail-closed).
	KillSwitchURL string

	// EncryptionKey is the symmetric key used for encrypting communications.
	EncryptionKey [32]byte

	// ServerPubKey is the server's public key for key exchange verification.
	ServerPubKey [32]byte

	// MaxRetries is the maximum number of consecutive connection failures
	// before the implant self-terminates.
	MaxRetries int

	// TransportOrder is the priority-ordered list of transport names to attempt.
	TransportOrder []string
}
