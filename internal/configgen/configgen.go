// Package configgen generates Xray configurations and VLESS links in memory.
package configgen

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/Muaytai/vpn-vless/internal/model"
)

const flow = "xtls-rprx-vision"

type vlessUser struct {
	ID   string `json:"id"`
	Flow string `json:"flow"`
}

type fallbackLimit struct {
	AfterBytes       int `json:"afterBytes"`
	BytesPerSec      int `json:"bytesPerSec"`
	BurstBytesPerSec int `json:"burstBytesPerSec"`
}

type serverReality struct {
	Target                string        `json:"target"`
	ServerNames           []string      `json:"serverNames"`
	PrivateKey            string        `json:"privateKey"`
	ShortIDs              []string      `json:"shortIds"`
	LimitFallbackUpload   fallbackLimit `json:"limitFallbackUpload"`
	LimitFallbackDownload fallbackLimit `json:"limitFallbackDownload"`
}

type clientReality struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	Password    string `json:"password"`
	ShortID     string `json:"shortId"`
}

type streamSettings struct {
	Network         string `json:"network"`
	Security        string `json:"security"`
	RealitySettings any    `json:"realitySettings"`
}

type inbound struct {
	Listen         string          `json:"listen,omitempty"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings"`
	StreamSettings *streamSettings `json:"streamSettings,omitempty"`
}

type routingRule struct {
	Type        string   `json:"type"`
	IP          []string `json:"ip"`
	OutboundTag string   `json:"outboundTag"`
}

type routing struct {
	DomainStrategy string        `json:"domainStrategy"`
	Rules          []routingRule `json:"rules"`
}

type config struct {
	Inbounds  []inbound  `json:"inbounds"`
	Outbounds []outbound `json:"outbounds"`
	Routing   *routing   `json:"routing,omitempty"`
}

// ServerConfig returns a server configuration containing only active users.
// The returned bytes contain credentials and must be handled as secrets.
func ServerConfig(s model.Server, users []model.User) ([]byte, error) {
	if s.Port < 1 || s.Port > 65535 {
		return nil, errors.New("invalid server port")
	}
	clients := make([]vlessUser, 0, len(users))
	for _, user := range users {
		if user.IsActive() {
			clients = append(clients, vlessUser{ID: user.UUID, Flow: flow})
		}
	}
	settings := struct {
		Clients    []vlessUser `json:"clients"`
		Decryption string      `json:"decryption"`
	}{clients, "none"}
	// These per-connection limits leave room for an ordinary TLS handshake
	// while throttling sustained unauthenticated fallback traffic.
	limit := fallbackLimit{AfterBytes: 65536, BytesPerSec: 16384, BurstBytesPerSec: 32768}
	return json.MarshalIndent(config{
		Inbounds: []inbound{{
			Port: s.Port, Protocol: "vless", Settings: settings,
			StreamSettings: &streamSettings{Network: "tcp", Security: "reality", RealitySettings: serverReality{
				Target: s.Target, ServerNames: []string{s.ServerName}, PrivateKey: s.PrivateKey,
				ShortIDs: []string{s.ShortID}, LimitFallbackUpload: limit, LimitFallbackDownload: limit,
			}},
		}},
		Outbounds: []outbound{
			{Tag: "direct", Protocol: "freedom", Settings: struct{}{}},
			{Tag: "blocked", Protocol: "blackhole", Settings: struct{}{}},
		},
		Routing: &routing{
			DomainStrategy: "IPIfNonMatch",
			Rules: []routingRule{{Type: "field", OutboundTag: "blocked", IP: []string{
				"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
				"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
				"198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
				"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
			}}},
		},
	}, "", "  ")
}

func endpoint(s model.Server) (string, error) {
	if s.Port < 1 || s.Port > 65535 {
		return "", errors.New("invalid server port")
	}
	host := s.Endpoint
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if host == "" || strings.ContainsAny(host, "/?#@[]") {
		return "", errors.New("invalid server endpoint")
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return "", errors.New("invalid server endpoint")
	}
	return host, nil
}

// UserLink returns a credential-bearing VLESS link for an active user.
func UserLink(s model.Server, user model.User) (string, error) {
	if !user.IsActive() {
		return "", errors.New("user is not active")
	}
	host, err := endpoint(s)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"type": {"tcp"}, "security": {"reality"}, "encryption": {"none"},
		"flow": {flow}, "sni": {s.ServerName}, "fp": {"chrome"},
		"pbk": {s.PublicKey}, "sid": {s.ShortID},
	}
	u := url.URL{Scheme: "vless", User: url.User(user.UUID), Host: net.JoinHostPort(host, strconv.Itoa(s.Port)), RawQuery: q.Encode(), Fragment: user.Name}
	return u.String(), nil
}

// ClientConfig returns a credential-bearing Xray client configuration.
func ClientConfig(s model.Server, user model.User, socksPort int) ([]byte, error) {
	if !user.IsActive() {
		return nil, errors.New("user is not active")
	}
	host, err := endpoint(s)
	if err != nil {
		return nil, err
	}
	if socksPort < 1 || socksPort > 65535 {
		return nil, errors.New("invalid SOCKS port")
	}
	settings := struct {
		Address    string `json:"address"`
		Port       int    `json:"port"`
		ID         string `json:"id"`
		Encryption string `json:"encryption"`
		Flow       string `json:"flow"`
	}{host, s.Port, user.UUID, "none", flow}
	return json.MarshalIndent(config{
		Inbounds: []inbound{{Listen: "127.0.0.1", Port: socksPort, Protocol: "socks", Settings: struct {
			UDP bool `json:"udp"`
		}{true}}},
		Outbounds: []outbound{{Protocol: "vless", Settings: settings,
			StreamSettings: &streamSettings{Network: "tcp", Security: "reality", RealitySettings: clientReality{
				ServerName: s.ServerName, Fingerprint: "chrome", Password: s.PublicKey, ShortID: s.ShortID,
			}},
		}},
	}, "", "  ")
}
