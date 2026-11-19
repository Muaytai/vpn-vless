package configgen

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Muaytai/vpn-vless/internal/model"
)

func fixtures() (model.Server, model.User) {
	return model.Server{
		Endpoint: "2001:db8::1", Port: 443, ServerName: "www.example.com", Target: "www.example.com:443",
		PrivateKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ShortID: "abcd1234",
	}, model.User{Name: "Тест & #1", UUID: "5783a3e7-e373-51cd-8642-c83782b807c5", Active: true}
}

func object(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestServerConfig(t *testing.T) {
	s, user := fixtures()
	now := time.Now()
	inactive := model.User{UUID: "inactive", Active: false}
	revoked := model.User{UUID: "revoked", Active: true, RevokedAt: &now}
	data, err := ServerConfig(s, []model.User{inactive, user, revoked})
	if err != nil {
		t.Fatal(err)
	}
	root := object(t, data)
	ib := root["inbounds"].([]any)[0].(map[string]any)
	if ib["port"] != float64(443) || ib["protocol"] != "vless" {
		t.Fatal("incorrect inbound")
	}
	settings := ib["settings"].(map[string]any)
	want := []any{map[string]any{"id": user.UUID, "flow": flow}}
	if !reflect.DeepEqual(settings["clients"], want) {
		t.Fatal("incorrect clients")
	}
	if settings["decryption"] != "none" {
		t.Fatal("incorrect decryption")
	}
	stream := ib["streamSettings"].(map[string]any)
	if stream["network"] != "tcp" || stream["security"] != "reality" {
		t.Fatal("incorrect transport")
	}
	reality := stream["realitySettings"].(map[string]any)
	if reality["target"] != s.Target || reality["privateKey"] != s.PrivateKey || !reflect.DeepEqual(reality["serverNames"], []any{s.ServerName}) || !reflect.DeepEqual(reality["shortIds"], []any{s.ShortID}) {
		t.Fatal("incorrect server REALITY settings")
	}
	for _, key := range []string{"limitFallbackUpload", "limitFallbackDownload"} {
		limit := reality[key].(map[string]any)
		if limit["afterBytes"] != float64(65536) || limit["bytesPerSec"] != float64(16384) || limit["burstBytesPerSec"] != float64(32768) {
			t.Fatalf("incorrect fallback limit %s", key)
		}
	}
	outbounds := root["outbounds"].([]any)
	if outbounds[0].(map[string]any)["protocol"] != "freedom" || outbounds[1].(map[string]any)["protocol"] != "blackhole" {
		t.Fatal("incorrect server outbounds")
	}
	routing := root["routing"].(map[string]any)
	rule := routing["rules"].([]any)[0].(map[string]any)
	if routing["domainStrategy"] != "IPIfNonMatch" || rule["outboundTag"] != "blocked" {
		t.Fatal("private address routing must use blocked outbound after DNS resolution")
	}
	for _, cidr := range []string{"127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"} {
		if !strings.Contains(string(data), cidr) {
			t.Fatalf("missing blocked range %s", cidr)
		}
	}
	if strings.Contains(string(data), inactive.UUID) || strings.Contains(string(data), revoked.UUID) || strings.Contains(string(data), user.Name) {
		t.Fatal("unexpected user data")
	}
	empty, err := ServerConfig(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings = object(t, empty)["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)
	if !reflect.DeepEqual(settings["clients"], []any{}) {
		t.Fatal("empty clients must be an array")
	}
}

func TestClientConfig(t *testing.T) {
	s, user := fixtures()
	data, err := ClientConfig(s, user, 1080)
	if err != nil {
		t.Fatal(err)
	}
	root := object(t, data)
	ib := root["inbounds"].([]any)[0].(map[string]any)
	if ib["listen"] != "127.0.0.1" || ib["port"] != float64(1080) || ib["protocol"] != "socks" || ib["settings"].(map[string]any)["udp"] != true {
		t.Fatal("incorrect SOCKS inbound")
	}
	ob := root["outbounds"].([]any)[0].(map[string]any)
	settings := ob["settings"].(map[string]any)
	if ob["protocol"] != "vless" || settings["address"] != s.Endpoint || settings["port"] != float64(s.Port) || settings["id"] != user.UUID || settings["flow"] != flow || settings["encryption"] != "none" {
		t.Fatal("incorrect outbound")
	}
	stream := ob["streamSettings"].(map[string]any)
	reality := stream["realitySettings"].(map[string]any)
	if stream["network"] != "tcp" || stream["security"] != "reality" || reality["serverName"] != s.ServerName || reality["fingerprint"] != "chrome" || reality["password"] != s.PublicKey || reality["shortId"] != s.ShortID {
		t.Fatal("incorrect client REALITY settings")
	}
	if strings.Contains(string(data), s.PrivateKey) || strings.Contains(string(data), user.Name) {
		t.Fatal("unexpected user information")
	}
}

func TestUserLink(t *testing.T) {
	s, user := fixtures()
	s.PublicKey = "key+/=&?"
	s.ServerName = "a&b.example"
	link, err := UserLink(s, user)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "vless" || u.Host != "[2001:db8::1]:443" || u.User.Username() != user.UUID || u.Fragment != user.Name {
		t.Fatal("incorrect link authority or fragment")
	}
	want := url.Values{"type": {"tcp"}, "security": {"reality"}, "encryption": {"none"}, "flow": {flow}, "sni": {s.ServerName}, "fp": {"chrome"}, "pbk": {s.PublicKey}, "sid": {s.ShortID}}
	if !reflect.DeepEqual(u.Query(), want) {
		t.Fatal("incorrect query parameters")
	}
	if !strings.Contains(link, "%26") || !strings.Contains(link, "%2B") {
		t.Fatal("query parameters not escaped")
	}
	s.Endpoint = "[2001:db8::1]"
	if link, err = UserLink(s, user); err != nil || !strings.Contains(link, "@[2001:db8::1]:443") {
		t.Fatal("bracketed IPv6 endpoint not supported")
	}
}

func TestInactiveExports(t *testing.T) {
	s, user := fixtures()
	now := time.Now()
	for _, u := range []model.User{{UUID: user.UUID}, {UUID: user.UUID, Active: true, RevokedAt: &now}} {
		if link, err := UserLink(s, u); err == nil || link != "" {
			t.Fatal("inactive user link exported")
		}
		if data, err := ClientConfig(s, u, 1080); err == nil || data != nil {
			t.Fatal("inactive user config exported")
		}
	}
}

func TestInvalidPorts(t *testing.T) {
	s, user := fixtures()
	for _, p := range []int{-1, 0, 65536} {
		if data, err := ClientConfig(s, user, p); err == nil || data != nil {
			t.Fatal("invalid SOCKS port accepted")
		}
		s.Port = p
		if _, err := ServerConfig(s, nil); err == nil {
			t.Fatal("invalid server port accepted")
		}
		if _, err := UserLink(s, user); err == nil {
			t.Fatal("invalid endpoint port accepted")
		}
	}
}

// Set XRAY_TEST_BINARY to the v1.260327.0 executable to check actual parsing.
func TestXrayCompatibility(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("XRAY_TEST_BINARY not set")
	}
	version, err := exec.Command(binary, "version").Output()
	if err != nil || !strings.Contains(string(version), "Xray 26.3.27") {
		t.Fatal("XRAY_TEST_BINARY must be Xray 26.3.27")
	}
	s, user := fixtures()
	server, err := ServerConfig(s, []model.User{user})
	if err != nil {
		t.Fatal(err)
	}
	client, err := ClientConfig(s, user, 1080)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"server": server, "client": client} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(binary, "run", "-test", "-config", path).CombinedOutput(); err != nil {
				t.Fatalf("Xray rejected config: %v\n%s", err, output)
			}
		})
	}
}
