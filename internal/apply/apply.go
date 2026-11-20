// Package apply deploys an Xray configuration to the local systemd service.
package apply

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
)

const (
	configDir  = "/etc/vpn-vless"
	configPath = configDir + "/config.json"
	xrayPath   = "/usr/local/bin/xray"
)

// Apply validates and atomically installs config, then restarts vpn-vless.
// It must run as root on Linux with the vpn-vless group already installed.
// Once installed, the validated config is never rolled back. A failed restart
// or active check stops the service; neither check confirms network reachability.
func Apply(config []byte) error {
	if runtime.GOOS != "linux" {
		return errors.New("apply requires Linux")
	}
	if os.Geteuid() != 0 {
		return errors.New("apply requires root")
	}
	group, err := user.LookupGroup("vpn-vless")
	if err != nil {
		return fmt.Errorf("lookup vpn-vless group: %w", err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return errors.New("invalid vpn-vless group ID")
	}
	if err := ensureDir(configDir); err != nil {
		return err
	}
	return applyConfig(configDir, configPath, gid, config, runCommand)
}

type commandRunner func(string, ...string) error

// Command output is deliberately discarded: Xray diagnostics may contain secrets.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func ensureDir(dir string) error {
	if err := os.Mkdir(dir, 0750); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("create config directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspect config directory: %w", err)
	}
	// Lstat returns symlink metadata directly; for a symlink IsDir() is false,
	// so symlinks are always rejected here without an extra ModeSymlink check.
	if !info.IsDir() {
		return errors.New("config directory must be a real directory")
	}
	return nil
}

func applyConfig(dir, path string, gid int, config []byte, run commandRunner) (result error) {
	// Serialize validation, installation, and service operations.
	lock := filepath.Join(dir, ".apply.lock")
	if err := os.Mkdir(lock, 0700); err != nil {
		return fmt.Errorf("acquire apply lock (remove stale lock manually after verifying no apply is running): %w", err)
	}
	defer func() {
		if err := os.Remove(lock); err != nil {
			result = errors.Join(result, fmt.Errorf("remove apply lock: %w", err))
		}
	}()

	if err := checkPrevious(path); err != nil {
		return err
	}
	// Restrict traversal while correcting the directory ownership.
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("restrict config directory: %w", err)
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		return fmt.Errorf("set config directory owner: %w", err)
	}
	if err := os.Chmod(dir, 0750); err != nil {
		return fmt.Errorf("set config directory permissions: %w", err)
	}
	newFile, err := writeTemp(dir, gid, 0640, config)
	if err != nil {
		return err
	}
	defer func() {
		if newFile != "" {
			if err := os.Remove(newFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				result = errors.Join(result, fmt.Errorf("remove temporary config: %w", err))
			}
		}
	}()
	if err := run(xrayPath, "run", "-test", "-config", newFile); err != nil {
		return fmt.Errorf("validate Xray config: %w; apply did not occur and previous access may persist", err)
	}
	if err := os.Rename(newFile, path); err != nil {
		return fmt.Errorf("install config: %w", err)
	}
	newFile = ""
	if err := run("systemctl", "restart", "vpn-vless"); err != nil {
		return errors.Join(fmt.Errorf("restart vpn-vless failed; validated new config remains installed: %w", err), wrapStop(run("systemctl", "stop", "vpn-vless")))
	}
	if err := run("systemctl", "is-active", "--quiet", "vpn-vless"); err != nil {
		return errors.Join(fmt.Errorf("vpn-vless is not active after restart; validated new config remains installed: %w", err), wrapStop(run("systemctl", "stop", "vpn-vless")))
	}
	return nil
}

func checkPrevious(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect previous config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("previous config is not a regular file")
	}
	return nil
}

func writeTemp(dir string, gid int, mode os.FileMode, data []byte) (name string, result error) {
	file, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return "", fmt.Errorf("create temporary config: %w", err)
	}
	name = file.Name()
	defer func() {
		if result != nil {
			result = errors.Join(result, wrapRemove(os.Remove(name)))
			name = ""
		}
	}()
	if err := file.Chown(0, gid); err != nil {
		result = fmt.Errorf("set temporary config owner: %w", err)
	} else if err := file.Chmod(mode); err != nil {
		result = fmt.Errorf("set temporary config permissions: %w", err)
	} else if _, err := file.Write(data); err != nil {
		result = fmt.Errorf("write temporary config: %w", err)
	} else if err := file.Sync(); err != nil {
		result = fmt.Errorf("sync temporary config: %w", err)
	}
	if err := file.Close(); err != nil {
		result = errors.Join(result, fmt.Errorf("close temporary config: %w", err))
	}
	return name, result
}

func wrapRemove(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("remove config: %w", err)
}

func wrapStop(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("stop vpn-vless after failed deployment: %w; WARNING: the old process may still be active and previous access may persist", err)
}
