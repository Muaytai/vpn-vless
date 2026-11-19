//go:build linux

package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func privateTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func expectUnsafeOpen(t *testing.T, path, message string) {
	t.Helper()
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatalf("Open(%q) succeeded; want error containing %q", path, message)
	}
	if !strings.Contains(err.Error(), message) {
		t.Fatalf("Open(%q): %v; want error containing %q", path, err, message)
	}
}

func TestOpenRejectsUnsafePermissions(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "vpn.db")
		expectUnsafeOpen(t, path, "database directory")
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("database created in unsafe directory: %v", err)
		}
		info, err := os.Lstat(dir)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatalf("directory permissions changed: %v, %v", info, err)
		}
	})
	t.Run("file", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "vpn.db")
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		expectUnsafeOpen(t, path, "permissions")
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != 0644 || info.Size() != 0 {
			t.Fatalf("database file changed: %v, %v", info, err)
		}
	})
}

func TestOpenRejectsSymlinksAndNonRegularFiles(t *testing.T) {
	t.Run("directory symlink", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		expectUnsafeOpen(t, filepath.Join(link, "vpn.db"), "not a real directory")
		if _, err := os.Lstat(filepath.Join(target, "vpn.db")); !os.IsNotExist(err) {
			t.Fatalf("database created through directory symlink: %v", err)
		}
	})
	for _, dangling := range []bool{false, true} {
		name := "file symlink"
		if dangling {
			name = "dangling file symlink"
		}
		t.Run(name, func(t *testing.T) {
			dir := privateTestDir(t)
			target := filepath.Join(dir, "target")
			if !dangling {
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(dir, "vpn.db")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			expectUnsafeOpen(t, link, "not a regular file")
		})
	}
	t.Run("file is directory", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "vpn.db")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		expectUnsafeOpen(t, path, "not a regular file")
	})
	t.Run("file is fifo", func(t *testing.T) {
		path := filepath.Join(privateTestDir(t), "vpn.db")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		expectUnsafeOpen(t, path, "not a regular file")
	})
}

func TestOpenRejectsOtherOwner(t *testing.T) {
	for _, directory := range []bool{true, false} {
		name := "file"
		if directory {
			name = "directory"
		}
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "private")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "vpn.db")
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
			target := path
			if directory {
				target = dir
			}
			uid := os.Geteuid() + 1
			if err := os.Chown(target, uid, -1); err != nil {
				if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
					t.Skipf("cannot change owner: %v", err)
				}
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chown(target, os.Geteuid(), -1) })
			expectUnsafeOpen(t, path, "owner uid")
			info, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			if info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
				t.Fatal("owner changed")
			}
		})
	}
}
