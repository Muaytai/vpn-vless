package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Muaytai/vpn-vless/internal/model"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	filename := "vpn #1?.db"
	if runtime.GOOS == "windows" {
		filename = "vpn #1.db"
	}
	path := filepath.Join(t.TempDir(), "private", filename)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestInitialize(t *testing.T) {
	s, path := openTestStore(t)
	if _, err := s.Server(); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("uninitialized server: %v", err)
	}
	created := time.Date(2024, 1, 2, 3, 4, 5, 123, time.FixedZone("offset", 3600))
	want := model.Server{Endpoint: "example.com", Port: 443, ServerName: "host", Target: "target", PrivateKey: "secret", PublicKey: "public", ShortID: "ab", CreatedAt: created}
	if err := s.Initialize(want); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(model.Server{}); err == nil {
		t.Fatal("second initialization succeeded")
	}
	got, err := s.Server()
	if err != nil {
		t.Fatal(err)
	}
	want.CreatedAt = want.CreatedAt.UTC()
	if got != want {
		t.Fatalf("server = %#v, want %#v", got, want)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, err := s2.Server(); err != nil || got != want {
		t.Fatalf("reopened server = %#v, %v", got, err)
	}
}

func TestUsers(t *testing.T) {
	s, _ := openTestStore(t)
	if users, err := s.Users(false); err != nil || len(users) != 0 {
		t.Fatalf("empty users = %v, %v", users, err)
	}
	before := time.Now().UTC()
	alice, err := s.AddUser("Alice_1", "uuid-one")
	if err != nil {
		t.Fatal(err)
	}
	if !alice.Active || alice.RevokedAt != nil || alice.CreatedAt.Location() != time.UTC || alice.CreatedAt.Before(before) || alice.CreatedAt.After(time.Now().UTC()) {
		t.Fatalf("new user = %#v", alice)
	}
	if _, err := s.AddUser("bob-2", "uuid-two"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser("Alice_1", "other"); err == nil {
		t.Fatal("duplicate name accepted")
	}
	if _, err := s.AddUser("other", "uuid-one"); err == nil {
		t.Fatal("duplicate UUID accepted")
	}
	got, err := s.User("Alice_1")
	if err != nil || got != alice {
		t.Fatalf("user = %#v, %v", got, err)
	}
	if _, err := s.User("missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing user: %v", err)
	}
	if err := s.RevokeUser("Alice_1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.User("Alice_1")
	if err != nil || got.Active || got.RevokedAt == nil || got.RevokedAt.Location() != time.UTC || got.RevokedAt.Before(got.CreatedAt) {
		t.Fatalf("revoked user = %#v, %v", got, err)
	}
	if err := s.RevokeUser("Alice_1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("repeat revoke: %v", err)
	}
	if err := s.RevokeUser("missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing revoke: %v", err)
	}
	all, err := s.Users(false)
	if err != nil || len(all) != 2 || all[0].Name != "Alice_1" || all[1].Name != "bob-2" {
		t.Fatalf("all users = %#v, %v", all, err)
	}
	active, err := s.Users(true)
	if err != nil || len(active) != 1 || active[0].Name != "bob-2" {
		t.Fatalf("active users = %#v, %v", active, err)
	}
	if _, err := s.AddUser("Alice_1", "uuid-three"); err == nil {
		t.Fatal("revoked name reused")
	}
	if _, err := s.AddUser("new", "uuid-one"); err == nil {
		t.Fatal("revoked UUID reused")
	}
}

func TestInvalidInputsAndClosedStore(t *testing.T) {
	s, _ := openTestStore(t)
	for _, name := range []string{"", ".", "..", "a/b", `a\b`, "a b", "é", "a' OR 1=1--", "a\x00b"} {
		if _, err := s.AddUser(name, "uuid"); err == nil {
			t.Errorf("accepted name %q", name)
		}
		if _, err := s.User(name); err == nil {
			t.Errorf("looked up invalid name %q", name)
		}
		if err := s.RevokeUser(name); err == nil {
			t.Errorf("revoked invalid name %q", name)
		}
	}
	if _, err := s.AddUser("valid", ""); err == nil {
		t.Error("accepted empty UUID")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Users(false); err == nil {
		t.Error("listed users on closed database")
	}
	if err := s.Initialize(model.Server{}); err == nil {
		t.Error("initialized closed database")
	}
	if _, err := Open(""); err == nil {
		t.Error("opened empty path")
	}
}

func TestPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not supported on Windows")
	}
	_, path := openTestStore(t)
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Dir(path), 0700}, {path, 0600}} {
		info, err := os.Stat(item.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() & ^item.mode != 0 {
			t.Errorf("%s permissions = %o", item.path, info.Mode().Perm())
		}
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	// Opening a read-only database may fail; either way it must not relax its mode.
	other, _ := Open(path)
	if other != nil {
		other.Close()
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatalf("existing permissions changed: %v, %v", info, err)
	}
}
