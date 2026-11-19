//go:build linux

package store

import (
	"fmt"
	"os"
	"syscall"
)

func checkStorePath(path string, directory bool) error {
	kind := "database file"
	if directory {
		kind = "database directory"
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s %q: %w", kind, path, err)
	}
	if directory && !info.IsDir() {
		return fmt.Errorf("unsafe %s %q: not a real directory", kind, path)
	}
	if !directory && !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe %s %q: not a regular file", kind, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unsafe %s %q: cannot determine owner", kind, path)
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unsafe %s %q: owner uid %d does not match effective uid %d", kind, path, stat.Uid, os.Geteuid())
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("unsafe %s %q: permissions %04o allow group or other access", kind, path, info.Mode().Perm())
	}
	return nil
}
