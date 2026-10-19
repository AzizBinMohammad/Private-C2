//go:build windows

package pivot

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// NamedPipeProxy exposes a local named pipe and relays each client to target.
type NamedPipeProxy struct {
	pipeName   string
	target     string
	targetHost string
	check      ScopeCheck

	stop  chan struct{}
	once  sync.Once
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns map[windows.Handle]struct{}
}

// StartNamedPipeProxy creates the pipe server and accepts clients in the
// background. pipeName may be a bare name or a full \\.\pipe\ path.
func StartNamedPipeProxy(pipeName, target string, check ScopeCheck) (*NamedPipeProxy, error) {
	pipeName = strings.TrimSpace(pipeName)
	if pipeName == "" {
		return nil, fmt.Errorf("a pipe name is required")
	}
	if !strings.HasPrefix(pipeName, `\\.\pipe\`) {
		pipeName = `\\.\pipe\` + strings.TrimPrefix(pipeName, `\`)
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("target must be host:port: %w", err)
	}
	if check == nil {
		return nil, fmt.Errorf("a scope check is required")
	}
	p := &NamedPipeProxy{
		pipeName:   pipeName,
		target:     target,
		targetHost: host,
		check:      check,
		stop:       make(chan struct{}),
		conns:      make(map[windows.Handle]struct{}),
	}
	go p.acceptLoop()
	return p, nil
}

// Addr is the full pipe path.
func (p *NamedPipeProxy) Addr() string { return p.pipeName }

// Close unblocks the accept loop and waits for active relays.
func (p *NamedPipeProxy) Close() error {
	p.once.Do(func() {
		close(p.stop)
		name, _ := windows.UTF16PtrFromString(p.pipeName)
		h, err := windows.CreateFile(name,
			windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
			windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			_ = windows.CloseHandle(h)
		}
		p.mu.Lock()
		for handle := range p.conns {
			_ = windows.CloseHandle(handle)
		}
		p.mu.Unlock()
	})
	p.wg.Wait()
	return nil
}

func (p *NamedPipeProxy) acceptLoop() {
	for {
		select {
		case <-p.stop:
			return
		default:
		}

		name, err := windows.UTF16PtrFromString(p.pipeName)
		if err != nil {
			return
		}
		handle, err := windows.CreateNamedPipe(name,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT,
			1, 64*1024, 64*1024, 0, nil)
		if err != nil {
			return
		}

		connectErr := windows.ConnectNamedPipe(handle, nil)
		connected := connectErr == nil
		if !connected {
			// ERROR_PIPE_CONNECTED means a client won the race; continue.
			if connectErr == windows.ERROR_PIPE_CONNECTED {
				connected = true
			}
		}
		if !connected {
			_ = windows.CloseHandle(handle)
			select {
			case <-p.stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}

		select {
		case <-p.stop:
			_ = windows.CloseHandle(handle)
			return
		default:
		}
		p.mu.Lock()
		p.conns[handle] = struct{}{}
		p.mu.Unlock()
		p.wg.Add(1)
		go func(h windows.Handle) {
			defer p.wg.Done()
			defer func() {
				p.mu.Lock()
				delete(p.conns, h)
				p.mu.Unlock()
				_ = windows.CloseHandle(h)
			}()
			p.relay(h)
		}(handle)
	}
}

func (p *NamedPipeProxy) relay(h windows.Handle) {
	if err := p.check(context.Background(), p.targetHost); err != nil {
		return
	}
	conn, err := net.DialTimeout("tcp", p.target, 15*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	pipe := pipeConn{h: h}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, pipe)
		closeWrite(conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(pipe, conn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

type pipeConn struct {
	h windows.Handle
}

func (c pipeConn) Read(p []byte) (int, error) {
	var n uint32
	if err := windows.ReadFile(c.h, p, &n, nil); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return int(n), nil
}

func (c pipeConn) Write(p []byte) (int, error) {
	var n uint32
	if err := windows.WriteFile(c.h, p, &n, nil); err != nil {
		return int(n), err
	}
	return int(n), nil
}
