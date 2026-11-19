package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Muaytai/vpn-vless/internal/configgen"
)

type xrayProcess struct {
	cmd  *exec.Cmd
	done chan error
	log  *xrayLog
}

type xrayLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *xrayLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *xrayLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func startXray(t *testing.T, binary, configPath string) *xrayProcess {
	t.Helper()
	p := &xrayProcess{cmd: exec.Command(binary, "run", "-config", configPath), done: make(chan error, 1), log: &xrayLog{}}
	p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start Xray: %v", err)
	}
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *xrayProcess) stop(t *testing.T) {
	t.Helper()
	if p.cmd == nil {
		return
	}
	select {
	case err := <-p.done:
		t.Errorf("Xray exited unexpectedly: %v; log: %s", err, p.log.String())
	default:
		if err := p.cmd.Process.Kill(); err != nil {
			t.Errorf("kill Xray: %v", err)
		}
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for Xray to exit")
		}
	}
	p.cmd = nil
}

func waitXrayPort(t *testing.T, p *xrayProcess, port int) {
	t.Helper()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			p.cmd = nil
			t.Fatalf("Xray exited before listening on %s: %v; log: %s", address, err, p.log.String())
		default:
		}
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			if err := conn.Close(); err != nil {
				t.Fatalf("close readiness connection: %v", err)
			}
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Xray did not listen on %s: %v; log: %s", address, lastErr, p.log.String())
}

func freeXrayPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func writeXrayConfig(t *testing.T, dir, name string, config []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(config); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func localXrayServerConfig(t *testing.T, config []byte) []byte {
	t.Helper()
	var root map[string]json.RawMessage
	if err := json.Unmarshal(config, &root); err != nil {
		t.Fatal(err)
	}
	var inbounds []map[string]json.RawMessage
	if err := json.Unmarshal(root["inbounds"], &inbounds); err != nil || len(inbounds) != 1 {
		t.Fatalf("invalid server inbounds: %v", err)
	}
	inbounds[0]["listen"] = json.RawMessage(`"127.0.0.1"`)
	var err error
	root["inbounds"], err = json.Marshal(inbounds)
	if err != nil {
		t.Fatal(err)
	}
	config, err = json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestXrayIntegration(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if os.Getenv("XRAY_INTEGRATION") != "1" || binary == "" {
		t.Skip("set XRAY_INTEGRATION=1 and XRAY_TEST_BINARY to run")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VPN_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	serverPort := freeXrayPort(t)
	socksPort := freeXrayPort(t)
	for socksPort == serverPort {
		socksPort = freeXrayPort(t)
	}
	requireSuccess(t, call("init", "--endpoint", "127.0.0.1", "--port", strconv.Itoa(serverPort), "--reality-host", "www.cloudflare.com"))
	requireSuccess(t, call("user", "add", "alice"))
	s := readStore(t)
	server, err := s.Server()
	if err != nil {
		t.Fatal(err)
	}
	user, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	users, err := s.Users(true)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := configgen.ServerConfig(server, users)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := configgen.ClientConfig(server, user, socksPort)
	if err != nil {
		t.Fatal(err)
	}
	configDir := t.TempDir()
	serverPath := writeXrayConfig(t, configDir, "server.json", localXrayServerConfig(t, serverConfig))
	clientPath := writeXrayConfig(t, configDir, "client.json", clientConfig)
	serverProcess := startXray(t, binary, serverPath)
	waitXrayPort(t, serverProcess, serverPort)
	clientProcess := startXray(t, binary, clientPath)
	waitXrayPort(t, clientProcess, socksPort)

	const publicURL = "https://www.cloudflare.com/cdn-cgi/trace"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "local xray integration response")
	}))
	defer target.Close()
	proxyURL := &url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response, err := client.Get(publicURL)
	if err != nil {
		t.Fatalf("public request through Xray failed: %v; server: %s; client: %s", err, serverProcess.log.String(), clientProcess.log.String())
	}
	got, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected public response: status=%s body=%q read=%v close=%v", response.Status, got, readErr, closeErr)
	}

	response, err = client.Get(target.URL)
	if err == nil {
		response.Body.Close()
		t.Fatalf("localhost request through Xray received HTTP response: %s", response.Status)
	}
	t.Logf("localhost request through Xray failed as expected: %v", err)

	requireSuccess(t, call("user", "revoke", "alice"))
	users, err = s.Users(false)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err = configgen.ServerConfig(server, users)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serverConfig, []byte(user.UUID)) {
		t.Fatal("revoked user is still present in server configuration")
	}
	revokedPath := writeXrayConfig(t, configDir, "server-revoked.json", localXrayServerConfig(t, serverConfig))
	serverProcess.stop(t)
	serverProcess = startXray(t, binary, revokedPath)
	waitXrayPort(t, serverProcess, serverPort)
	waitXrayPort(t, clientProcess, socksPort)
	response, err = client.Get(publicURL)
	if err == nil {
		response.Body.Close()
		t.Fatalf("revoked credentials received HTTP response: %s", response.Status)
	}
	t.Logf("request with revoked credentials failed as expected: %v", err)
	select {
	case err := <-serverProcess.done:
		serverProcess.cmd = nil
		t.Fatal(fmt.Sprintf("server exited during revoked request: %v; log: %s", err, serverProcess.log.String()))
	case err := <-clientProcess.done:
		clientProcess.cmd = nil
		t.Fatal(fmt.Sprintf("client exited during revoked request: %v; log: %s", err, clientProcess.log.String()))
	default:
	}
}
