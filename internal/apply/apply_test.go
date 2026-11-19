package apply

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestCheckPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := checkPrevious(path); err != nil {
		t.Fatalf("missing config: %v", err)
	}
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrevious(path); err != nil {
		t.Fatalf("regular config: %v", err)
	}
	if err := checkPrevious(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory accepted: %v", err)
	}
}

func TestApplyRequiresLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux host")
	}
	if err := Apply(nil); err == nil || !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("Apply on non-Linux: %v", err)
	}
}

func TestErrorHelpers(t *testing.T) {
	if wrapRemove(nil) != nil || wrapStop(nil) != nil {
		t.Fatal("nil errors must remain nil")
	}
	err := errors.New("failure")
	if !errors.Is(wrapRemove(err), err) || !errors.Is(wrapStop(err), err) {
		t.Fatal("wrapped errors must retain their cause")
	}
	if !strings.Contains(wrapStop(err).Error(), "old process may still be active") {
		t.Fatal("stop failure must warn about the old process")
	}
}

func TestApplyConfig(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("ownership and Unix permissions require root on Linux")
	}

	const oldConfig = `{"clients":[{"id":"revoked-uuid"}]}`
	const newConfig = `{"clients":[]}`
	failure := errors.New("stub failure")
	stopFailure := errors.New("stub stop failure")
	tests := []struct {
		name         string
		existing     bool
		failCommand  string
		failStop     bool
		wantCommands []string
		wantConfig   string
		wantError    []string
	}{
		{"success", true, "", false, []string{"validate", "restart", "is-active"}, newConfig, nil},
		{"restart failure", true, "restart", false, []string{"validate", "restart", "stop"}, newConfig, []string{"restart", "new config remains installed"}},
		{"restart and stop failure", true, "restart", true, []string{"validate", "restart", "stop"}, newConfig, []string{"restart", "WARNING", "old process may still be active", "previous access may persist"}},
		{"inactive", true, "is-active", false, []string{"validate", "restart", "is-active", "stop"}, newConfig, []string{"not active", "new config remains installed"}},
		{"inactive and stop failure", true, "is-active", true, []string{"validate", "restart", "is-active", "stop"}, newConfig, []string{"not active", "WARNING", "old process may still be active"}},
		{"validate failure", true, "validate", false, []string{"validate"}, oldConfig, []string{"validate Xray config", "apply did not occur", "previous access may persist"}},
		{"restart without previous config", false, "restart", false, []string{"validate", "restart", "stop"}, newConfig, []string{"restart", "new config remains installed"}},
		{"validate without previous config", false, "validate", false, []string{"validate"}, "", []string{"validate Xray config", "apply did not occur"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if tc.existing {
				if err := os.WriteFile(path, []byte(oldConfig), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var commands []string
			run := func(name string, args ...string) error {
				var command string
				switch {
				case name == xrayPath && len(args) == 4 && args[0] == "run" && args[1] == "-test" && args[2] == "-config":
					command = "validate"
					data, err := os.ReadFile(args[3])
					if err != nil || string(data) != newConfig {
						t.Fatalf("validation input = %q, err = %v", data, err)
					}
				case name == "systemctl" && reflect.DeepEqual(args, []string{"restart", "vpn-vless"}):
					command = "restart"
				case name == "systemctl" && reflect.DeepEqual(args, []string{"is-active", "--quiet", "vpn-vless"}):
					command = "is-active"
				case name == "systemctl" && reflect.DeepEqual(args, []string{"stop", "vpn-vless"}):
					command = "stop"
				default:
					t.Fatalf("unexpected command: %s %v", name, args)
				}
				commands = append(commands, command)
				if command == tc.failCommand {
					return failure
				}
				if command == "stop" && tc.failStop {
					return stopFailure
				}
				return nil
			}
			err := applyConfig(dir, path, os.Getgid(), []byte(newConfig), run)
			if tc.failCommand == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if !errors.Is(err, failure) {
					t.Fatalf("error %v does not wrap failure", err)
				}
				if tc.failStop && !errors.Is(err, stopFailure) {
					t.Fatalf("error %v does not wrap stop failure", err)
				}
				for _, text := range tc.wantError {
					if !strings.Contains(err.Error(), text) {
						t.Errorf("error %q missing %q", err, text)
					}
				}
			}
			if !reflect.DeepEqual(commands, tc.wantCommands) {
				t.Errorf("commands = %v, want %v", commands, tc.wantCommands)
			}
			data, readErr := os.ReadFile(path)
			if tc.wantConfig == "" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("expected no config, got %q, err %v", data, readErr)
				}
			} else if readErr != nil || string(data) != tc.wantConfig {
				t.Fatalf("config = %q, err = %v; want %q", data, readErr, tc.wantConfig)
			}
			if tc.wantConfig == newConfig {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != 0640 {
					t.Errorf("permissions = %#o, want 0640", info.Mode().Perm())
				}
				stat := reflect.Indirect(reflect.ValueOf(info.Sys()))
				if !stat.IsValid() || stat.Kind() != reflect.Struct || !stat.FieldByName("Uid").IsValid() || !stat.FieldByName("Gid").IsValid() || stat.FieldByName("Uid").Uint() != 0 || stat.FieldByName("Gid").Uint() != uint64(os.Getgid()) {
					t.Errorf("owner/group = %v, want root:%d", info.Sys(), os.Getgid())
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "config.json" {
					t.Errorf("unexpected leftover file %q", entry.Name())
				}
			}
		})
	}
}
