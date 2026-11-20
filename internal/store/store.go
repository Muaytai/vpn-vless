package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Muaytai/vpn-vless/internal/model"
	_ "modernc.org/sqlite"
)

// Store holds the server configuration and its users.
type Store struct {
	db *sql.DB
}

// Open opens or creates a database at path. Existing permissions are not changed.
func Open(path string) (*Store, error) {
	if path == "" || path == ":memory:" {
		return nil, errors.New("database path must name a file")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	if err := checkStorePath(dir, true); err != nil {
		return nil, err
	}
	// Create the file before SQLite opens it, so it is never created with a
	// permissive mode. O_EXCL leaves existing file permissions untouched.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("create database file: %w", err)
	}
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, fmt.Errorf("close database file: %w", err)
		}
	}
	if err := checkStorePath(path, false); err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(path)
	if len(uriPath) > 0 && uriPath[0] != '/' {
		uriPath = "/" + uriPath
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("configure database: %w", err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		endpoint TEXT NOT NULL, port INTEGER NOT NULL, server_name TEXT NOT NULL,
		target TEXT NOT NULL, private_key TEXT NOT NULL, public_key TEXT NOT NULL,
		short_id TEXT NOT NULL, created_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS users (
		name TEXT PRIMARY KEY NOT NULL, uuid TEXT NOT NULL UNIQUE,
		active INTEGER NOT NULL CHECK (active IN (0, 1)),
		created_at TEXT NOT NULL, revoked_at TEXT,
		CHECK ((active = 1 AND revoked_at IS NULL) OR (active = 0 AND revoked_at IS NOT NULL))
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize database schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// Initialize stores the server configuration exactly once.
func (s *Store) Initialize(server model.Server) error {
	created := server.CreatedAt
	if created.IsZero() {
		created = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO settings
		(id, endpoint, port, server_name, target, private_key, public_key, short_id, created_at)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)`, server.Endpoint, server.Port,
		server.ServerName, server.Target, server.PrivateKey, server.PublicKey,
		server.ShortID, timestamp(created))
	if err != nil {
		return fmt.Errorf("initialize server: %w", err)
	}
	return nil
}

func (s *Store) Server() (model.Server, error) {
	var server model.Server
	var created string
	err := s.db.QueryRow(`SELECT endpoint, port, server_name, target, private_key, public_key, short_id, created_at FROM settings WHERE id = 1`).Scan(
		&server.Endpoint, &server.Port, &server.ServerName, &server.Target,
		&server.PrivateKey, &server.PublicKey, &server.ShortID, &created)
	if err != nil {
		return model.Server{}, fmt.Errorf("get server: %w", err)
	}
	server.CreatedAt, err = parseTimestamp(created)
	if err != nil {
		return model.Server{}, fmt.Errorf("parse server creation time: %w", err)
	}
	return server, nil
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Store) AddUser(name, uuid string) (model.User, error) {
	if !validName(name) {
		return model.User{}, errors.New("invalid user name")
	}
	if uuid == "" {
		return model.User{}, errors.New("empty user UUID")
	}
	user := model.User{Name: name, UUID: uuid, Active: true, CreatedAt: time.Now().UTC()}
	_, err := s.db.Exec(`INSERT INTO users (name, uuid, active, created_at, revoked_at) VALUES (?, ?, 1, ?, NULL)`, name, uuid, timestamp(user.CreatedAt))
	if err != nil {
		return model.User{}, fmt.Errorf("add user: %w", err)
	}
	return user, nil
}

func (s *Store) User(name string) (model.User, error) {
	if !validName(name) {
		return model.User{}, errors.New("invalid user name")
	}
	user, err := scanUser(s.db.QueryRow(`SELECT name, uuid, active, created_at, revoked_at FROM users WHERE name = ?`, name))
	if err != nil {
		return model.User{}, fmt.Errorf("get user: %w", err)
	}
	return user, nil
}

func (s *Store) Users(activeOnly bool) ([]model.User, error) {
	query := `SELECT name, uuid, active, created_at, revoked_at FROM users`
	if activeOnly {
		query += ` WHERE active = 1`
	}
	query += ` ORDER BY name`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := make([]model.User, 0)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("read user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

func (s *Store) RevokeUser(name string) error {
	if !validName(name) {
		return errors.New("invalid user name")
	}
	result, err := s.db.Exec(`UPDATE users SET active = 0, revoked_at = ? WHERE name = ? AND active = 1`, timestamp(time.Now()), name)
	if err != nil {
		return fmt.Errorf("revoke user: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke user: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("revoke user: %w", sql.ErrNoRows)
	}
	return nil
}

func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func parseTimestamp(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, value)
	return t.UTC(), err
}

func scanUser(row interface{ Scan(...any) error }) (model.User, error) {
	var user model.User
	var created string
	var revoked sql.NullString
	if err := row.Scan(&user.Name, &user.UUID, &user.Active, &created, &revoked); err != nil {
		return model.User{}, err
	}
	var err error
	user.CreatedAt, err = parseTimestamp(created)
	if err != nil {
		return model.User{}, fmt.Errorf("parse creation time: %w", err)
	}
	if revoked.Valid {
		t, err := parseTimestamp(revoked.String)
		if err != nil {
			return model.User{}, fmt.Errorf("parse revocation time: %w", err)
		}
		user.RevokedAt = &t
	}
	return user, nil
}
