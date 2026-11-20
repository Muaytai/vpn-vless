package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Muaytai/vpn-vless/internal/apply"
	"github.com/Muaytai/vpn-vless/internal/configgen"
	"github.com/Muaytai/vpn-vless/internal/model"
	"github.com/Muaytai/vpn-vless/internal/store"
	"github.com/gofrs/flock"
)

const help = `vpnctl — управление VLESS + REALITY

Порядок настройки:
  vpnctl init --endpoint IP_ИЛИ_ДОМЕН [--port 443] [--reality-host www.cloudflare.com]
  vpnctl user add NAME
  vpnctl server apply
  vpnctl user link NAME

Команды:
  user add NAME     добавить пользователя (после этого нужен server apply)
  user list         показать имена и состояния пользователей
  user revoke NAME  отозвать пользователя (после этого нужен server apply)
  user link NAME    вывести личную VLESS-ссылку
  user client [--socks-port PORT] NAME
                    вывести конфигурацию Xray-клиента (SOCKS, по умолчанию 1080)
  server render     вывести конфигурацию сервера
  server apply      проверить и применить конфигурацию на Linux (нужен root)

Нужен клиент Xray, WireGuard не подходит. Ссылки и конфигурации секретны.
Откройте выбранный TCP-порт сервера в брандмауэре и у провайдера.
Каталог данных задаётся VPN_DATA_DIR; по умолчанию /var/lib/vpn-vless на Linux
и ./data на Windows. Имена пользователей: латинские буквы, цифры, - и _.
`

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, apply.Apply); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}

func dataDir() string {
	if dir := os.Getenv("VPN_DATA_DIR"); dir != "" {
		return dir
	}
	if runtime.GOOS == "windows" {
		return "./data"
	}
	return "/var/lib/vpn-vless"
}

func run(args []string, out, errOut io.Writer, applyConfig func([]byte) error) (result error) {
	if len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help")) {
		_, err := io.WriteString(out, help)
		return err
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") && (args[0] == "init" || args[0] == "user" || args[0] == "server") {
		_, err := io.WriteString(out, help)
		return err
	}
	if len(args) == 3 && (args[2] == "--help" || args[2] == "-h") && (args[0] == "user" || args[0] == "server") {
		_, err := io.WriteString(out, help)
		return err
	}

	var server model.Server
	if args[0] == "init" {
		var err error
		server, err = parseInit(args[1:])
		if err != nil {
			return err
		}
	} else if err := validateCommand(args); err != nil {
		return err
	}

	dir := dataDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("создать каталог данных: %w", err)
	}
	lock := flock.New(filepath.Join(dir, "vpnctl.lock"))
	locked, err := lock.TryLock()
	if err != nil {
		return fmt.Errorf("заблокировать каталог данных: %w", err)
	}
	if !locked {
		return errors.New("каталог данных заблокирован другой командой vpnctl; повторите попытку позже")
	}
	defer func() {
		if err := lock.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("освободить блокировку каталога данных: %w", err))
		}
	}()

	s, err := store.Open(filepath.Join(dir, "vpn.db"))
	if err != nil {
		return fmt.Errorf("открыть хранилище: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			result = errors.Join(result, fmt.Errorf("закрыть хранилище: %w", err))
		}
	}()

	if args[0] == "init" {
		if err := s.Initialize(server); err != nil {
			return fmt.Errorf("инициализировать сервер (возможно, он уже инициализирован): %w", err)
		}
		_, err := fmt.Fprintln(out, "Сервер инициализирован. Добавьте пользователя и выполните vpnctl server apply.")
		return err
	}
	server, err = s.Server()
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("сервер не инициализирован; сначала выполните vpnctl init")
	}
	if err != nil {
		return fmt.Errorf("получить настройки сервера: %w", err)
	}
	if args[0] == "user" {
		return userCommand(s, server, args[1:], out, errOut)
	}
	users, err := s.Users(true)
	if err != nil {
		return fmt.Errorf("получить пользователей: %w", err)
	}
	config, err := configgen.ServerConfig(server, users)
	if err != nil {
		return fmt.Errorf("создать конфигурацию сервера: %w", err)
	}
	if args[1] == "render" {
		return printSecret(out, errOut, "Конфигурация сервера содержит секреты; храните её в безопасности.", string(config))
	}
	if err := applyConfig(config); err != nil {
		return fmt.Errorf("применить конфигурацию: %w", err)
	}
	_, err = fmt.Fprintln(out, "Конфигурация сервера применена.")
	return err
}

func validateCommand(args []string) error {
	if len(args) < 2 {
		return errors.New("неполная команда; используйте vpnctl --help")
	}
	if args[0] == "server" && (args[1] == "render" || args[1] == "apply") && len(args) == 2 {
		return nil
	}
	if args[0] == "user" {
		if args[1] == "list" && len(args) == 2 {
			return nil
		}
		if (args[1] == "add" || args[1] == "revoke" || args[1] == "link") && len(args) == 3 && args[2] != "" {
			return nil
		}
		if args[1] == "client" && len(args) >= 3 {
			return nil
		}
	}
	return errors.New("неизвестная команда или неверные аргументы; используйте vpnctl --help")
}

func parseInit(args []string) (model.Server, error) {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	endpoint := fs.String("endpoint", "", "IP или DNS-имя сервера")
	port := fs.Int("port", 443, "TCP-порт сервера")
	realityHost := fs.String("reality-host", "www.cloudflare.com", "DNS-имя REALITY")
	if err := fs.Parse(args); err != nil {
		return model.Server{}, errors.New("неверные параметры init; используйте vpnctl init --help")
	}
	if fs.NArg() != 0 {
		return model.Server{}, errors.New("лишние аргументы init")
	}
	if !validEndpoint(*endpoint) {
		return model.Server{}, errors.New("endpoint должен быть IPv4, IPv6 или корректным DNS-именем без порта")
	}
	if *port < 1 || *port > 65535 {
		return model.Server{}, errors.New("port должен быть от 1 до 65535")
	}
	if !validDNS(*realityHost) || net.ParseIP(*realityHost) != nil || numericIPv4Like(*realityHost) {
		return model.Server{}, errors.New("reality-host должен быть DNS-именем, а не IP-адресом")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return model.Server{}, fmt.Errorf("создать ключ X25519: %w", err)
	}
	shortID := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, shortID); err != nil {
		return model.Server{}, fmt.Errorf("создать short ID: %w", err)
	}
	return model.Server{
		Endpoint: *endpoint, Port: *port, ServerName: *realityHost,
		Target:     net.JoinHostPort(*realityHost, "443"),
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		ShortID:    hex.EncodeToString(shortID),
	}, nil
}

func validEndpoint(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	return !numericIPv4Like(host) && validDNS(host)
}

func numericIPv4Like(host string) bool {
	if host == "" {
		return false
	}
	for _, c := range host {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

func validDNS(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func userCommand(s *store.Store, server model.Server, args []string, out, errOut io.Writer) error {
	switch args[0] {
	case "add":
		uuid, err := newUUID()
		if err != nil {
			return fmt.Errorf("создать UUID: %w", err)
		}
		if _, err := s.AddUser(args[1], uuid); err != nil {
			return fmt.Errorf("добавить пользователя: %w", err)
		}
		_, err = fmt.Fprintln(out, "Пользователь добавлен. Для включения доступа выполните vpnctl server apply.")
		return err
	case "list":
		users, err := s.Users(false)
		if err != nil {
			return fmt.Errorf("получить пользователей: %w", err)
		}
		for _, user := range users {
			status := "revoked"
			if user.Active && user.RevokedAt == nil {
				status = "active"
			}
			if _, err := fmt.Fprintf(out, "%s\t%s\n", user.Name, status); err != nil {
				return err
			}
		}
		return nil
	case "revoke":
		if err := s.RevokeUser(args[1]); err != nil {
			return fmt.Errorf("отозвать пользователя: %w", err)
		}
		_, err := fmt.Fprintln(out, "Пользователь отозван. Доступ действительно отключится только после vpnctl server apply.")
		return err
	case "link":
		user, err := s.User(args[1])
		if err != nil {
			return fmt.Errorf("получить пользователя: %w", err)
		}
		if !user.IsActive() {
			return errors.New("пользователь отозван; выдача конфигурации запрещена")
		}
		link, err := configgen.UserLink(server, user)
		if err != nil {
			return fmt.Errorf("создать ссылку: %w", err)
		}
		return printSecret(out, errOut, "VLESS-ссылка содержит секрет; не передавайте её посторонним.", link)
	case "client":
		fs := flag.NewFlagSet("client", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		socksPort := fs.Int("socks-port", 1080, "SOCKS5 proxy port")
		if err := fs.Parse(args[1:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				_, writeErr := io.WriteString(out, help)
				return writeErr
			}
			return errors.New("неверные параметры client; используйте vpnctl --help")
		}
		if fs.NArg() != 1 || fs.Arg(0) == "" {
			return errors.New("неверные параметры client; используйте vpnctl --help")
		}
		user, err := s.User(fs.Arg(0))
		if err != nil {
			return fmt.Errorf("получить пользователя: %w", err)
		}
		if !user.IsActive() {
			return errors.New("пользователь отозван; выдача конфигурации запрещена")
		}
		config, err := configgen.ClientConfig(server, user, *socksPort)
		if err != nil {
			return fmt.Errorf("создать конфигурацию клиента: %w", err)
		}
		return printSecret(out, errOut, "Конфигурация клиента содержит секрет; не передавайте её посторонним.", string(config))
	}
	return errors.New("неизвестная команда пользователя")
}

func printSecret(out, errOut io.Writer, warning, value string) error {
	if _, err := fmt.Fprintln(errOut, "Внимание:", warning); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, value)
	return err
}
