package transport

import "context"

// Transport defines the interface that all implant communication
// channels must implement. Each transport handles connection management,
// sending data to the C2 server, and receiving responses.
type Transport interface {
	// Connect establishes the transport connection to the C2 server.
	Connect(ctx context.Context) error

	// Send transmits data to the C2 server over this transport.
	Send(data []byte) error

	// Recv receives data from the C2 server over this transport.
	Recv() ([]byte, error)

	// Close tears down the transport connection.
	Close() error

	// Name returns the transport's identifier (e.g., "mtls", "https", "dns").
	Name() string
}
