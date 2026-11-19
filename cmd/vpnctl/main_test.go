package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Muaytai/vpn-vless/internal/store"
	"github.com/gofrs/flock"
)

type cliResult struct {
	out, stderr string
	err         error
}

func call(args ...string) cliResult {
	var out, stderr bytes.Buffer
	err := run(args, &out, &stderr, func([]byte) error { return errors.New("unexpected apply") })
	return cliResult{out.String(), stderr.String(), err}
}

func requireSuccess(t *testing.T, r cliResult) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("command failed: %v; stderr: %s", r.err, r.stderr)
	}
}

func readStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(os.Getenv("VPN_DATA_DIR"), "vpn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func TestLifecycle(t *testing.T) {
	t.Setenv("VPN_DATA_DIR", filepath.Join(t.TempDir(), "data"))
	for _, args := range [][]string{{"user", "list"}, {"user", "add", "alice"}, {"user", "link", "alice"}, {"user", "client", "alice"}, {"user", "revoke", "alice"}, {"server", "render"}, {"server", "apply"}} {
		if r := call(args...); r.err == nil || !strings.Contains(r.err.Error(), "не инициализирован") {
			t.Fatalf("%v: expected uninitialized error, got %v", args, r.err)
		}
	}
	init := call("init", "--endpoint", "2001:db8::1", "--port", "8443", "--reality-host", "example.com")
	requireSuccess(t, init)
	s := readStore(t)
	server, err := s.Server()
	if err != nil {
		t.Fatal(err)
	}
	if server.Endpoint != "2001:db8::1" || server.Port != 8443 || server.ServerName != "example.com" || server.Target != "example.com:443" {
		t.Fatal("incorrect server settings")
	}
	private, err := base64.RawURLEncoding.DecodeString(server.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || server.PublicKey != base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatal("invalid X25519 key pair")
	}
	shortID, err := hex.DecodeString(server.ShortID)
	if err != nil || len(shortID) != 8 {
		t.Fatal("invalid short ID")
	}
	for _, secret := range []string{server.PrivateKey, server.PublicKey, server.ShortID} {
		if strings.Contains(init.out+init.stderr, secret) {
			t.Fatal("init leaked server credentials")
		}
	}
	if r := call("init", "--endpoint", "example.org"); r.err == nil {
		t.Fatal("duplicate initialization succeeded")
	}
	add := call("user", "add", "alice")
	requireSuccess(t, add)
	if !strings.Contains(add.out, "server apply") || strings.Contains(add.out+add.stderr, "vless://") {
		t.Fatal("add must mention apply and not print a link")
	}
	requireSuccess(t, call("user", "add", "bob"))
	if r := call("user", "add", "alice"); r.err == nil {
		t.Fatal("duplicate name succeeded")
	}
	alice, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.User("bob")
	if err != nil {
		t.Fatal(err)
	}
	uuidPattern := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidPattern.MatchString(alice.UUID) || !uuidPattern.MatchString(bob.UUID) || alice.UUID == bob.UUID {
		t.Fatal("UUIDs must be distinct random UUIDv4s")
	}
	list := call("user", "list")
	requireSuccess(t, list)
	if list.out != "alice\tactive\nbob\tactive\n" || strings.Contains(list.out+list.stderr+add.out+add.stderr, alice.UUID) || strings.Contains(list.out+list.stderr, bob.UUID) {
		t.Fatal("list must contain only names and statuses")
	}
	link := call("user", "link", "alice")
	requireSuccess(t, link)
	u, err := url.Parse(strings.TrimSpace(link.out))
	if err != nil || u.Scheme != "vless" || u.User.Username() != alice.UUID || u.Host != "[2001:db8::1]:8443" || u.Query().Get("pbk") != server.PublicKey || u.Query().Get("sid") != server.ShortID || u.Fragment != "alice" || !strings.Contains(link.stderr, "секрет") {
		t.Fatal("invalid link or missing secret warning")
	}
	client := call("user", "client", "alice")
	requireSuccess(t, client)
	var conf struct {
		Inbounds []struct {
			Listen, Protocol string
			Port             int
		}
		Outbounds []struct {
			Settings struct{ ID string }
		}
	}
	if json.Unmarshal([]byte(client.out), &conf) != nil || len(conf.Inbounds) != 1 || conf.Inbounds[0].Listen != "127.0.0.1" || conf.Inbounds[0].Port != 1080 || conf.Inbounds[0].Protocol != "socks" || len(conf.Outbounds) != 1 || conf.Outbounds[0].Settings.ID != alice.UUID || !strings.Contains(client.stderr, "секрет") || strings.Contains(client.out, server.PrivateKey) {
		t.Fatal("invalid client config or warning")
	}
	render := call("server", "render")
	requireSuccess(t, render)
	if !json.Valid([]byte(render.out)) || !strings.Contains(render.out, alice.UUID) || !strings.Contains(render.out, server.PrivateKey) || !strings.Contains(render.stderr, "секрет") {
		t.Fatal("invalid server render or warning")
	}
	revoke := call("user", "revoke", "alice")
	requireSuccess(t, revoke)
	if !strings.Contains(revoke.out, "только после") || !strings.Contains(revoke.out, "server apply") {
		t.Fatal("revoke must warn about apply")
	}
	for _, command := range []string{"link", "client"} {
		if r := call("user", command, "alice"); r.err == nil || r.out != "" {
			t.Fatalf("revoked user %s must fail without output", command)
		}
	}
	list = call("user", "list")
	requireSuccess(t, list)
	if list.out != "alice\trevoked\nbob\tactive\n" {
		t.Fatal("incorrect revoked status")
	}
	var applied []byte
	var stdout, stderr bytes.Buffer
	err = run([]string{"server", "apply"}, &stdout, &stderr, func(config []byte) error {
		applied = append([]byte(nil), config...)
		return nil
	})
	if err != nil || !json.Valid(applied) || bytes.Contains(applied, []byte(alice.UUID)) || !bytes.Contains(applied, []byte(bob.UUID)) || strings.Contains(stdout.String()+stderr.String(), bob.UUID) {
		t.Fatal("apply must receive active users only and not print secrets")
	}
	if r := call("server", "apply"); r.err == nil {
		t.Fatal("apply failure must propagate")
	}
}

func TestRandomServerKeys(t *testing.T) {
	first, err := parseInit([]string{"--endpoint", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseInit([]string{"--endpoint", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if first.PrivateKey == second.PrivateKey || first.PublicKey == second.PublicKey || first.ShortID == second.ShortID {
		t.Fatal("keys and short IDs must be random")
	}
	if first.Port != 443 || first.ServerName != "www.cloudflare.com" || first.Target != "www.cloudflare.com:443" {
		t.Fatal("incorrect defaults")
	}
}

func TestInitValidation(t *testing.T) {
	validEndpoints := []string{"127.0.0.1", "2001:db8::1", "example.com", "my-server.example", "localhost"}
	for _, endpoint := range validEndpoints {
		if _, err := parseInit([]string{"--endpoint", endpoint}); err != nil {
			t.Errorf("valid endpoint %q rejected: %v", endpoint, err)
		}
	}
	invalidEndpoints := []string{"", "  example.com", "example.com:443", "https://example.com", "a_b.com", "-a.com", "a-.com", "a..com", "256.1.2.3", "1.2.3.999", "[::1]", "fe80::1%eth0", "example.com/path", strings.Repeat("a", 64) + ".com"}
	for _, endpoint := range invalidEndpoints {
		if _, err := parseInit([]string{"--endpoint", endpoint}); err == nil {
			t.Errorf("invalid endpoint %q accepted", endpoint)
		}
	}
	for _, host := range []string{"", "127.0.0.1", "::1", "example.com:443", "https://example.com", "example.com/path", "a b.com", "a_b.com", "a..com", "[::1]", "256.1.2.3"} {
		if _, err := parseInit([]string{"--endpoint", "example.com", "--reality-host", host}); err == nil {
			t.Errorf("invalid reality host %q accepted", host)
		}
	}
	for _, port := range []string{"0", "-1", "65536", "abc"} {
		if _, err := parseInit([]string{"--endpoint", "example.com", "--port", port}); err == nil {
			t.Errorf("invalid port %q accepted", port)
		}
	}
	for _, port := range []string{"1", "65535"} {
		if _, err := parseInit([]string{"--endpoint", "example.com", "--port", port}); err != nil {
			t.Errorf("valid port %q rejected", port)
		}
	}
}

func TestHelpAndArgumentErrors(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"init", "--help"}, {"user", "--help"}, {"user", "add", "--help"}, {"server", "--help"}} {
		r := call(args...)
		requireSuccess(t, r)
		for _, text := range []string{"init", "user add", "server apply", "user link", "WireGuard", "TCP", "секрет"} {
			if !strings.Contains(r.out, text) {
				t.Errorf("help %v missing %s", args, text)
			}
		}
	}
	for _, args := range [][]string{{"other"}, {"user"}, {"user", "add"}, {"server", "render", "extra"}, {"user", "list", "extra"}, {"init", "--endpoint", "example.com", "extra"}} {
		if r := call(args...); r.err == nil {
			t.Errorf("invalid args %v accepted", args)
		}
	}
}

func TestProcessExitAndStreams(t *testing.T) {
	if os.Getenv("VPNCTL_TEST_SUBPROCESS") == "1" {
		main()
		return
	}
	dir := filepath.Join(t.TempDir(), "data")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(args ...string) (string, string, error) {
		cmd := exec.Command(exe, append([]string{"-test.run=^TestProcessExitAndStreams$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "VPNCTL_TEST_SUBPROCESS=1", "VPN_DATA_DIR="+dir)
		// The Go test runner passes its separator to the test; replace arguments in the child below.
		var out, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &stderr
		err := cmd.Run()
		return out.String(), stderr.String(), err
	}
	out, stderr, err := invoke("init", "--endpoint", "example.com")
	if err != nil {
		t.Fatalf("init subprocess: %v: %s", err, stderr)
	}
	if strings.Contains(out, "vless://") {
		t.Fatal("init printed link")
	}
	if _, stderr, err = invoke("user", "add", "alice"); err != nil {
		t.Fatalf("add subprocess: %v: %s", err, stderr)
	}
	out, stderr, err = invoke("user", "link", "alice")
	if err != nil || !strings.HasPrefix(out, "vless://") || !strings.Contains(stderr, "секрет") {
		t.Fatal("link subprocess did not separate secret and warning")
	}
	if _, _, err = invoke("user", "add", "alice"); err == nil {
		t.Fatal("duplicate user subprocess must exit nonzero")
	}
}

func TestApplyLockProcess(t *testing.T) {
	if os.Getenv("VPNCTL_TEST_LOCK_HOLDER") != "1" {
		return
	}
	var out, stderr bytes.Buffer
	err := run([]string{"server", "apply"}, &out, &stderr, func(config []byte) error {
		if !json.Valid(config) {
			return errors.New("invalid configuration")
		}
		if _, err := fmt.Fprintln(os.Stdout, "ready"); err != nil {
			return err
		}
		_, err := io.ReadAll(os.Stdin)
		return err
	})
	if err != nil {
		t.Fatalf("apply: %v; stderr: %s", err, stderr.String())
	}
}

func TestDataDirectoryLockAcrossProcesses(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("VPN_DATA_DIR", dir)
	requireSuccess(t, call("init", "--endpoint", "example.com"))
	requireSuccess(t, call("user", "add", "alice"))
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0700 {
			t.Fatalf("data directory permissions: %o", info.Mode().Perm())
		}
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(args ...string) (string, error) {
		t.Helper()
		cmd := exec.Command(exe, append([]string{"-test.run=^TestProcessExitAndStreams$", "--"}, args...)...)
		cmd.Env = append(os.Environ(), "VPNCTL_TEST_SUBPROCESS=1", "VPN_DATA_DIR="+dir)
		output, err := cmd.CombinedOutput()
		return string(output), err
	}
	startApply := func() (*exec.Cmd, io.WriteCloser, *bytes.Buffer) {
		t.Helper()
		cmd := exec.Command(exe, "-test.run=^TestApplyLockProcess$")
		cmd.Env = append(os.Environ(), "VPNCTL_TEST_LOCK_HOLDER=1", "VPN_DATA_DIR="+dir)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			stdin.Close()
			if cmd.ProcessState == nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		})
		ready := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(stdout).ReadString('\n')
			ready <- line
		}()
		select {
		case line := <-ready:
			if line != "ready\n" && line != "ready\r\n" {
				cmd.Wait()
				t.Fatalf("apply did not start: %q; %s", line, stderr.String())
			}
		case <-time.After(30 * time.Second):
			t.Fatal("timed out waiting for apply")
		}
		return cmd, stdin, &stderr
	}

	for _, terminate := range []bool{false, true} {
		cmd, stdin, stderr := startApply()
		for _, args := range [][]string{
			{"user", "revoke", "alice"}, {"user", "add", "bob"},
			{"server", "apply"}, {"server", "render"}, {"user", "list"},
			{"init", "--endpoint", "example.com"},
		} {
			output, err := invoke(args...)
			if err == nil || !strings.Contains(output, "заблокирован другой командой") {
				t.Fatalf("%v during apply: expected lock error, got %v: %s", args, err, output)
			}
		}
		if output, err := invoke("--help"); err != nil || !strings.Contains(output, "server apply") {
			t.Fatalf("help during apply: %v: %s", err, output)
		}
		if terminate {
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err == nil {
				t.Fatal("killed process exited successfully")
			}
		} else {
			if err := stdin.Close(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("apply failed: %v: %s", err, stderr.String())
			}
		}
		if output, err := invoke("user", "list"); err != nil || !strings.Contains(output, "alice\tactive") || strings.Contains(output, "bob") {
			t.Fatalf("blocked mutations changed data or lock not released: %v: %s", err, output)
		}
	}
	s := readStore(t)
	alice, err := s.User("alice")
	if err != nil {
		t.Fatal(err)
	}
	if output, err := invoke("user", "revoke", "alice"); err != nil {
		t.Fatalf("revoke after release: %v: %s", err, output)
	}
	render := call("server", "render")
	requireSuccess(t, render)
	if strings.Contains(render.out, alice.UUID) {
		t.Fatal("revoked user appears in server configuration")
	}
}

func TestLockBeforeOpeningDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	t.Setenv("VPN_DATA_DIR", dir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lock := flock.New(filepath.Join(dir, "vpnctl.lock"))
	locked, err := lock.TryLock()
	if err != nil || !locked {
		t.Fatalf("acquire test lock: %v", err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	})
	if r := call("user", "list"); r.err == nil || !strings.Contains(r.err.Error(), "заблокирован другой командой") {
		t.Fatalf("expected lock error, got %v", r.err)
	}
	if _, err := os.Stat(filepath.Join(dir, "vpn.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("database was opened before locking: %v", err)
	}
	for _, args := range [][]string{{"--help"}, {"init", "--help"}, {"user", "add", "--help"}, {"server", "--help"}} {
		requireSuccess(t, call(args...))
	}
}

func init() {
	if os.Getenv("VPNCTL_TEST_SUBPROCESS") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				main()
				os.Exit(0)
			}
		}
		fmt.Fprintln(os.Stderr, "missing subprocess separator")
		os.Exit(2)
	}
}
