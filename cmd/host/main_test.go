package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/hanzoai/cloud"
)

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		prev, existed := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("unsetenv %s: %v", k, err)
		}
		k, prev, existed := k, prev, existed
		t.Cleanup(func() {
			if existed {
				_ = os.Setenv(k, prev)
			} else {
				_ = os.Unsetenv(k)
			}
		})
	}
}

func captureLogger() (logf func(string, ...any), lines func() string) {
	var mu sync.Mutex
	var buf strings.Builder
	return func(format string, args ...any) {
			mu.Lock()
			defer mu.Unlock()
			fmt.Fprintf(&buf, format+"\n", args...)
		}, func() string {
			mu.Lock()
			defer mu.Unlock()
			return buf.String()
		}
}

func TestEnsureMasterKeyMintMode0600AndLog(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "master.key")
	logf, logs := captureLogger()

	key, minted, err := ensureMasterKey(keyPath, logf)
	if err != nil {
		t.Fatalf("ensureMasterKey: %v", err)
	}
	if !minted {
		t.Fatal("minted = false, want true on first boot")
	}

	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 {
		t.Fatalf("minted key invalid: len=%d err=%v", len(raw), err)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat %s: %v", keyPath, err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("key file mode = %#o, want 0600", perm)
		}
	}

	disk, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read %s: %v", keyPath, err)
	}
	if strings.TrimSpace(string(disk)) != key {
		t.Fatalf("on-disk key mismatch")
	}

	out := logs()
	if !strings.Contains(out, "minted") || !strings.Contains(out, keyPath) {
		t.Fatalf("expected minted log mentioning %s, got %q", keyPath, out)
	}
	if strings.Contains(out, key) {
		t.Fatal("log output leaked master key material")
	}
}

func TestEnsureMasterKeyReuseExisting(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "master.key")
	logf1, _ := captureLogger()

	firstKey, minted, err := ensureMasterKey(keyPath, logf1)
	if err != nil || !minted {
		t.Fatalf("first boot: minted=%v err=%v", minted, err)
	}

	logf2, logs2 := captureLogger()
	secondKey, minted2, err := ensureMasterKey(keyPath, logf2)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if minted2 {
		t.Fatal("minted = true on second boot, want false")
	}
	if secondKey != firstKey {
		t.Fatal("second boot did not reuse existing master key")
	}

	out := logs2()
	if !strings.Contains(out, "loaded") || !strings.Contains(out, keyPath) {
		t.Fatalf("expected loaded log mentioning %s, got %q", keyPath, out)
	}
	if strings.Contains(out, firstKey) {
		t.Fatal("log output leaked master key material")
	}
}

func TestEnsureMasterKeyExclusiveCreateConcurrent(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "master.key")
	const workers = 8

	start := make(chan struct{})
	type result struct {
		key    string
		minted bool
		err    error
	}
	results := make([]result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			k, m, err := ensureMasterKey(keyPath, nil)
			results[idx] = result{key: k, minted: m, err: err}
		}(i)
	}
	close(start)
	wg.Wait()

	var wantKey string
	mintCount := 0
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("worker %d failed: %v", i, r.err)
		}
		if r.minted {
			mintCount++
		}
		if wantKey == "" {
			wantKey = r.key
		} else if r.key != wantKey {
			t.Fatalf("worker %d observed divergent key", i)
		}
	}
	if mintCount != 1 {
		t.Fatalf("mintCount = %d, want exactly 1 exclusive creator", mintCount)
	}
}

func TestEnsureMasterKeyFailedWrite(t *testing.T) {
	t.Run("unwritable_parent_path", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("seed blocker: %v", err)
		}
		keyPath := filepath.Join(blocker, "master.key")
		if _, _, err := ensureMasterKey(keyPath, nil); err == nil {
			t.Fatalf("ensureMasterKey(%q) = nil, want error", keyPath)
		}
	})

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Run("readonly_dir", func(t *testing.T) {
			roDir := filepath.Join(t.TempDir(), "ro")
			if err := os.Mkdir(roDir, 0o500); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })

			keyPath := filepath.Join(roDir, "master.key")
			if _, _, err := ensureMasterKey(keyPath, nil); err == nil {
				t.Fatalf("ensureMasterKey(%q) = nil, want error in read-only dir", keyPath)
			}
		})
	}

	t.Run("mid_write_io_failure_cleans_up", func(t *testing.T) {
		keyPath := filepath.Join(t.TempDir(), "master.key")
		orig := writeKeyFile
		writeKeyFile = func(f *os.File, _ string) error {
			_ = f.Close()
			return errors.New("simulated disk full")
		}
		t.Cleanup(func() { writeKeyFile = orig })

		if _, _, err := ensureMasterKey(keyPath, nil); err == nil {
			t.Fatal("ensureMasterKey = nil, want write error")
		}
		if _, err := os.Stat(keyPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected partial key file to be removed after write failure, got err=%v", err)
		}
	})
}

func TestEnsureLocalHostEnvFailedMasterKeyWriteLeavesEnvUnset(t *testing.T) {
	unsetEnv(t,
		"XDG_DATA_HOME",
		"CLOUD_LISTEN",
		"CLOUD_ADDR",
		"PORT",
		"CLOUD_DATA_DIR",
		"CLOUD_ZAP_LISTEN",
		"CLOUD_ENABLE_STAGED",
		"CLOUD_KMS_MASTER_KEY_REF",
		"CLOUD_DEV_UNENCRYPTED",
	)
	xdg := t.TempDir()
	t.Setenv("XDG_DATA_HOME", xdg)

	// Place a directory where master.key belongs so reading/writing it fails on every OS.
	stateDir := filepath.Join(xdg, "hanzo", "host")
	if err := os.MkdirAll(filepath.Join(stateDir, "master.key"), 0o700); err != nil {
		t.Fatalf("seed directory at master.key: %v", err)
	}

	if err := ensureLocalHostEnv(nil, nil); err == nil {
		t.Fatal("ensureLocalHostEnv = nil, want error when master.key cannot be read/written")
	}
	if got := os.Getenv("CLOUD_KMS_MASTER_KEY_REF"); got != "" {
		t.Fatal("CLOUD_KMS_MASTER_KEY_REF was set despite master.key persistence failure")
	}
}

func TestEnsureLocalHostEnvLoopbackDefault(t *testing.T) {
	baseEnv := []string{
		"XDG_DATA_HOME",
		"CLOUD_LISTEN",
		"CLOUD_ADDR",
		"PORT",
		"CLOUD_DATA_DIR",
		"CLOUD_ZAP_LISTEN",
		"CLOUD_ENABLE_STAGED",
		"CLOUD_KMS_MASTER_KEY_REF",
		"CLOUD_DEV_UNENCRYPTED",
	}

	t.Run("bare_invocation_defaults_to_loopback", func(t *testing.T) {
		unsetEnv(t, baseEnv...)
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		logf, logs := captureLogger()

		if err := ensureLocalHostEnv(nil, logf); err != nil {
			t.Fatalf("ensureLocalHostEnv: %v", err)
		}
		if got := os.Getenv("CLOUD_LISTEN"); got != defaultHostListenAddr {
			t.Fatalf("CLOUD_LISTEN = %q, want %q", got, defaultHostListenAddr)
		}
		if !isLoopbackAddr(os.Getenv("CLOUD_LISTEN")) {
			t.Fatalf("default CLOUD_LISTEN %q is not loopback", os.Getenv("CLOUD_LISTEN"))
		}
		if got := cloud.LoadConfig().ListenAddr; got != defaultHostListenAddr {
			t.Fatalf("cloud.LoadConfig().ListenAddr = %q, want %q", got, defaultHostListenAddr)
		}
		if got := os.Getenv("CLOUD_ENABLE_STAGED"); got != "functions" {
			t.Fatalf("CLOUD_ENABLE_STAGED = %q, want functions on loopback default", got)
		}
		key := os.Getenv("CLOUD_KMS_MASTER_KEY_REF")
		if key == "" {
			t.Fatal("expected CLOUD_KMS_MASTER_KEY_REF to be populated")
		}
		if strings.Contains(logs(), key) {
			t.Fatal("logs leaked CLOUD_KMS_MASTER_KEY_REF")
		}
	})

	t.Run("respects_CLOUD_LISTEN_and_skips_staged_on_non_loopback", func(t *testing.T) {
		unsetEnv(t, baseEnv...)
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		t.Setenv("CLOUD_LISTEN", ":9099")

		if err := ensureLocalHostEnv(nil, nil); err != nil {
			t.Fatalf("ensureLocalHostEnv: %v", err)
		}
		if got := os.Getenv("CLOUD_LISTEN"); got != ":9099" {
			t.Fatalf("CLOUD_LISTEN = %q, want :9099", got)
		}
		if _, set := os.LookupEnv("CLOUD_ENABLE_STAGED"); set {
			t.Fatalf("CLOUD_ENABLE_STAGED auto-enabled for non-loopback listener")
		}
	})

	t.Run("respects_PORT_and_skips_staged_on_non_loopback", func(t *testing.T) {
		unsetEnv(t, baseEnv...)
		t.Setenv("XDG_DATA_HOME", t.TempDir())
		t.Setenv("PORT", "4321")

		if err := ensureLocalHostEnv(nil, nil); err != nil {
			t.Fatalf("ensureLocalHostEnv: %v", err)
		}
		if got := os.Getenv("CLOUD_LISTEN"); got != "" {
			t.Fatalf("CLOUD_LISTEN = %q, want unset when PORT is provided", got)
		}
		if got := cloud.LoadConfig().ListenAddr; got != ":4321" {
			t.Fatalf("cloud.LoadConfig().ListenAddr = %q, want :4321", got)
		}
		if _, set := os.LookupEnv("CLOUD_ENABLE_STAGED"); set {
			t.Fatalf("CLOUD_ENABLE_STAGED auto-enabled for non-loopback PORT")
		}
	})

	t.Run("respects_addr_flag", func(t *testing.T) {
		unsetEnv(t, baseEnv...)
		t.Setenv("XDG_DATA_HOME", t.TempDir())

		if err := ensureLocalHostEnv([]string{"-addr", "127.0.0.1:4567"}, nil); err != nil {
			t.Fatalf("ensureLocalHostEnv: %v", err)
		}
		if got := os.Getenv("CLOUD_LISTEN"); got != "" {
			t.Fatalf("CLOUD_LISTEN = %q, want unset when -addr is passed", got)
		}
		if got := os.Getenv("CLOUD_ENABLE_STAGED"); got != "functions" {
			t.Fatalf("CLOUD_ENABLE_STAGED = %q, want functions for loopback -addr", got)
		}
	})

	t.Run("respects_non_loopback_addr_flag_without_auto_enabling_staged", func(t *testing.T) {
		unsetEnv(t, baseEnv...)
		t.Setenv("XDG_DATA_HOME", t.TempDir())

		if err := ensureLocalHostEnv([]string{"-addr=0.0.0.0:4567"}, nil); err != nil {
			t.Fatalf("ensureLocalHostEnv: %v", err)
		}
		if got := os.Getenv("CLOUD_LISTEN"); got != "" {
			t.Fatalf("CLOUD_LISTEN = %q, want unset when -addr is passed", got)
		}
		if _, set := os.LookupEnv("CLOUD_ENABLE_STAGED"); set {
			t.Fatalf("CLOUD_ENABLE_STAGED auto-enabled for non-loopback -addr")
		}
	})
}
