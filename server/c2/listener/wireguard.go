package listener

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// WireGuardListener implements a WireGuard tunnel endpoint stub.
// It wraps an mTLS listener inside a WireGuard tunnel for additional
// network-layer encryption and NAT traversal.
type WireGuardListener struct {
	BaseListener
	peers      map[string]*WGPeer
	peersMu    sync.RWMutex
	inner      Listener // wrapped listener (typically mTLS)
	privateKey string
	listenPort int
	cancelFunc context.CancelFunc
}

// WGPeer represents a WireGuard peer configuration.
type WGPeer struct {
	PublicKey    string
	AllowedIPs   []string
	Endpoint     string
	PresharedKey string
	Connected    bool
}

// WireGuardConfig holds the configuration for a WireGuard listener.
type WireGuardConfig struct {
	ID           string
	BindAddr     string
	EngagementID string
	PrivateKey   string
	ListenPort   int
	InnerListener Listener
}

// NewWireGuardListener creates a new WireGuard tunnel endpoint stub.
func NewWireGuardListener(cfg WireGuardConfig) (*WireGuardListener, error) {
	if cfg.PrivateKey == "" {
		return nil, fmt.Errorf("WireGuard private key is required")
	}

	return &WireGuardListener{
		BaseListener: NewBaseListener(cfg.ID, "wireguard", cfg.BindAddr, cfg.EngagementID),
		peers:        make(map[string]*WGPeer),
		privateKey:   cfg.PrivateKey,
		listenPort:   cfg.ListenPort,
		inner:        cfg.InnerListener,
	}, nil
}

// Start initializes the WireGuard tunnel and starts the inner listener.
// TODO: Integrate with a userspace WireGuard implementation (e.g., wireguard-go).
func (w *WireGuardListener) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	w.cancelFunc = cancel
	w.SetActive(true)

	log.Printf("[wireguard] listener %s started on %s (port %d)", w.id, w.bindAddr, w.listenPort)
	log.Printf("[wireguard] TODO: integrate userspace WireGuard tunnel")

	// If an inner listener is configured, start it on the tunnel interface.
	if w.inner != nil {
		return w.inner.Start(ctx)
	}

	// Block until context is cancelled.
	<-ctx.Done()
	return nil
}

// Stop shuts down the WireGuard tunnel and inner listener.
func (w *WireGuardListener) Stop() error {
	w.SetActive(false)
	if w.cancelFunc != nil {
		w.cancelFunc()
	}
	if w.inner != nil {
		return w.inner.Stop()
	}
	return nil
}

// ID returns the listener's unique identifier.
func (w *WireGuardListener) ID() string { return w.id }

// Type returns the listener type.
func (w *WireGuardListener) Type() string { return w.listenerType }

// Addr returns the listener's bind address.
func (w *WireGuardListener) Addr() string { return w.bindAddr }

// AddPeer adds a WireGuard peer to the tunnel.
func (w *WireGuardListener) AddPeer(peer *WGPeer) error {
	if peer.PublicKey == "" {
		return fmt.Errorf("peer public key is required")
	}

	w.peersMu.Lock()
	defer w.peersMu.Unlock()
	w.peers[peer.PublicKey] = peer

	log.Printf("[wireguard] added peer %s (endpoint: %s)", peer.PublicKey[:8]+"...", peer.Endpoint)
	// TODO: Apply peer configuration to the userspace WireGuard device.
	return nil
}

// RemovePeer removes a WireGuard peer from the tunnel.
func (w *WireGuardListener) RemovePeer(publicKey string) error {
	w.peersMu.Lock()
	defer w.peersMu.Unlock()

	if _, ok := w.peers[publicKey]; !ok {
		return fmt.Errorf("peer %s not found", publicKey)
	}
	delete(w.peers, publicKey)

	log.Printf("[wireguard] removed peer %s", publicKey[:8]+"...")
	// TODO: Remove peer from the userspace WireGuard device.
	return nil
}

// ListPeers returns all configured peers.
func (w *WireGuardListener) ListPeers() []*WGPeer {
	w.peersMu.RLock()
	defer w.peersMu.RUnlock()

	peers := make([]*WGPeer, 0, len(w.peers))
	for _, p := range w.peers {
		peers = append(peers, p)
	}
	return peers
}
