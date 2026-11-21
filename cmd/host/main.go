// Command host is the local network daemon spawned by `hanzo network start` (#4).
//
// It shares the fused composition root with cmd/cloud (`cloud.Serve(apps.Wire(), nil)`),
// while setting user-writable local defaults for loopback HTTP (`127.0.0.1:3690`),
// the state directory, ZAP unix socket (`host.zap.sock`), and persistent master
// key when launched without environment or flag overrides.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/hanzoai/cloud"
	"github.com/hanzoai/cloud/apps"
)

const defaultHostListenAddr = "127.0.0.1:3690"

// writeKeyFile persists and closes a newly created master key file. Overridden
// only in tests to simulate mid-write I/O failures.
var writeKeyFile = writeAndCloseMasterKey

func hostStateDir() string {
	if xdg := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); xdg != "" {
		return filepath.Join(xdg, "hanzo", "host")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "hanzo", "host")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "Application Support", "hanzo", "host")
	}
	return filepath.Join(home, ".local", "share", "hanzo", "host")
}

func devUnencrypted() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CLOUD_DEV_UNENCRYPTED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// flagValue returns the last value passed for any of names in args, stopping at
// "--" to match Go's standard flag parsing rules.
func flagValue(args []string, names ...string) (string, bool) {
	matches := func(name string) bool {
		for _, want := range names {
			if name == want {
				return true
			}
		}
		return false
	}

	var val string
	var found bool
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		trimmed := strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-")
		if name, v, hasEq := strings.Cut(trimmed, "="); hasEq {
			if matches(name) {
				val, found = v, true
			}
			continue
		}
		if matches(trimmed) && i+1 < len(args) {
			i++
			val, found = args[i], true
		}
	}
	return val, found
}

// isLoopbackAddr reports whether addr is a host:port whose host is localhost
// or a loopback IP (127.0.0.0/8, ::1).
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	return strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback()
}

// resolveListenAddr determines the effective HTTP listen address from CLI args
// and environment variables, reporting shouldDefault=true when none are set.
func resolveListenAddr(args []string) (addr string, shouldDefault bool) {
	if v, ok := flagValue(args, "addr", "listen"); ok {
		return v, false
	}
	if v := strings.TrimSpace(os.Getenv("CLOUD_LISTEN")); v != "" {
		return v, false
	}
	if v := strings.TrimSpace(os.Getenv("CLOUD_ADDR")); v != "" {
		return v, false
	}
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		if strings.IndexFunc(port, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
			return ":" + port, false
		}
		return port, false
	}
	return defaultHostListenAddr, true
}

func writeAndCloseMasterKey(f *os.File, encoded string) error {
	_, werr := f.WriteString(encoded + "\n")
	var serr error
	if werr == nil {
		serr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	return cerr
}

// waitAndReadMasterKey reads a master key file, briefly retrying if it is
// transiently empty while a concurrent first boot finishes writing its key.
func waitAndReadMasterKey(keyPath string) (string, error) {
	const attempts = 40
	for i := 0; i < attempts; i++ {
		b, err := os.ReadFile(keyPath)
		if err != nil {
			return "", fmt.Errorf("read master key %s: %w", keyPath, err)
		}
		if k := strings.TrimSpace(string(b)); k != "" {
			return k, nil
		}
		if i+1 < attempts {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return "", fmt.Errorf("master key file %s is empty", keyPath)
}

// ensureMasterKey loads an existing base64 master key from keyPath or mints a
// new 32-byte key with O_CREATE|O_EXCL (mode 0600) so concurrent first boots
// cannot overwrite each other with different keys. It logs whether the key was
// loaded or minted (never the key material) and fails closed on any I/O error.
func ensureMasterKey(keyPath string, logf func(format string, args ...any)) (key string, minted bool, err error) {
	b, err := os.ReadFile(keyPath)
	if err == nil {
		k := strings.TrimSpace(string(b))
		if k == "" {
			k, err = waitAndReadMasterKey(keyPath)
			if err != nil {
				return "", false, err
			}
		}
		if logf != nil {
			logf("host: loaded master key from %s", keyPath)
		}
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", false, fmt.Errorf("read master key %s: %w", keyPath, err)
	}

	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", false, fmt.Errorf("generate master key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw[:])

	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			k, readErr := waitAndReadMasterKey(keyPath)
			if readErr != nil {
				return "", false, readErr
			}
			if logf != nil {
				logf("host: loaded master key from %s", keyPath)
			}
			return k, false, nil
		}
		return "", false, fmt.Errorf("create master key %s: %w", keyPath, err)
	}

	if err := writeKeyFile(f, encoded); err != nil {
		_ = os.Remove(keyPath)
		return "", false, fmt.Errorf("write master key %s: %w", keyPath, err)
	}

	if logf != nil {
		logf("host: minted master key at %s", keyPath)
	}
	return encoded, true, nil
}

// ensureLocalHostEnv configures safe machine-local defaults for cmd/host before
// delegating to cloud.Serve.
func ensureLocalHostEnv(args []string, logf func(format string, args ...any)) error {
	stateDir := hostStateDir()
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create host state dir %s: %w", stateDir, err)
	}

	effectiveListen, shouldDefault := resolveListenAddr(args)
	if shouldDefault {
		if err := os.Setenv("CLOUD_LISTEN", defaultHostListenAddr); err != nil {
			return fmt.Errorf("set CLOUD_LISTEN: %w", err)
		}
	}

	if _, hasDataDirFlag := flagValue(args, "data-dir"); !hasDataDirFlag && os.Getenv("CLOUD_DATA_DIR") == "" {
		dataDir := filepath.Join(stateDir, "data")
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return fmt.Errorf("create host data dir %s: %w", dataDir, err)
		}
		if err := os.Setenv("CLOUD_DATA_DIR", dataDir); err != nil {
			return fmt.Errorf("set CLOUD_DATA_DIR: %w", err)
		}
	}

	if _, hasZapFlag := flagValue(args, "zap"); !hasZapFlag && os.Getenv("CLOUD_ZAP_LISTEN") == "" && runtime.GOOS != "windows" {
		if err := os.Setenv("CLOUD_ZAP_LISTEN", filepath.Join(stateDir, "host.zap.sock")); err != nil {
			return fmt.Errorf("set CLOUD_ZAP_LISTEN: %w", err)
		}
	}

	// Only auto-enable staged functions when binding a loopback HTTP listener
	// and the caller did not explicitly configure CLOUD_ENABLE_STAGED.
	if _, set := os.LookupEnv("CLOUD_ENABLE_STAGED"); !set && isLoopbackAddr(effectiveListen) {
		if err := os.Setenv("CLOUD_ENABLE_STAGED", "functions"); err != nil {
			return fmt.Errorf("set CLOUD_ENABLE_STAGED: %w", err)
		}
	}

	if _, hasKeyFlag := flagValue(args, "kms-master-key-ref"); !hasKeyFlag && os.Getenv("CLOUD_KMS_MASTER_KEY_REF") == "" && !devUnencrypted() {
		keyPath := filepath.Join(stateDir, "master.key")
		key, _, err := ensureMasterKey(keyPath, logf)
		if err != nil {
			return err
		}
		if err := os.Setenv("CLOUD_KMS_MASTER_KEY_REF", key); err != nil {
			return fmt.Errorf("set CLOUD_KMS_MASTER_KEY_REF: %w", err)
		}
	}

	return nil
}

func main() {
	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
	if err := ensureLocalHostEnv(os.Args[1:], logf); err != nil {
		fmt.Fprintf(os.Stderr, "host: %v\n", err)
		os.Exit(1)
	}
	if err := cloud.Serve(apps.Wire(), nil); err != nil {
		fmt.Fprintf(os.Stderr, "host: %v\n", err)
		os.Exit(1)
	}
}
