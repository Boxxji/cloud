package cloud

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrepareZAPSocketDoesNotDeleteRegularFile(t *testing.T) {
	dir := t.TempDir()
	const sentinel = "keep-this-regular-file"

	cases := []struct {
		name string
		path string
		addr string
	}{
		{
			name: "dot_sock_suffix",
			path: filepath.Join(dir, "keep.sock"),
			addr: filepath.Join(dir, "keep.sock"),
		},
		{
			name: "zap_scheme_dot_sock",
			path: filepath.Join(dir, "schemed.sock"),
			addr: "zap://" + filepath.Join(dir, "schemed.sock"),
		},
	}
	if runtime.GOOS != "windows" {
		// On Unix, t.TempDir() begins with "/", exercising the leading-"/" check
		// for a regular file without a ".sock" suffix.
		noSuffix := filepath.Join(dir, "regular-file")
		cases = append(cases, struct {
			name string
			path string
			addr string
		}{
			name: "leading_slash_without_sock_suffix",
			path: noSuffix,
			addr: noSuffix,
		})
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(tc.path, []byte(sentinel), 0o600); err != nil {
				t.Fatalf("seed regular file: %v", err)
			}

			if err := prepareZAPSocket(tc.addr); err == nil {
				t.Fatalf("prepareZAPSocket(%q) = nil, want error for regular file", tc.addr)
			}

			got, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("regular file %q was removed or unreadable: %v", tc.path, err)
			}
			if string(got) != sentinel {
				t.Fatalf("regular file content = %q, want %q", string(got), sentinel)
			}
		})
	}
}

func TestPrepareZAPSocketDoesNotDeleteDirectoryOrSymlink(t *testing.T) {
	dir := t.TempDir()

	t.Run("directory", func(t *testing.T) {
		p := filepath.Join(dir, "dir.sock")
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := prepareZAPSocket(p); err == nil {
			t.Fatalf("prepareZAPSocket(%q) = nil, want error for directory", p)
		}
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() {
			t.Fatalf("directory %q missing after prepareZAPSocket: info=%v err=%v", p, info, err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := filepath.Join(dir, "target.txt")
		if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
			t.Fatalf("seed target: %v", err)
		}
		link := filepath.Join(dir, "link.sock")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if err := prepareZAPSocket(link); err == nil {
			t.Fatalf("prepareZAPSocket(%q) = nil, want error for symlink", link)
		}
		info, err := os.Lstat(link)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink %q missing after prepareZAPSocket: info=%v err=%v", link, info, err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("symlink target %q missing: %v", target, err)
		}
	})
}

func TestPrepareZAPSocketRemovesStaleUnixSocket(t *testing.T) {
	// Keep the temp path short to stay well under Unix sun_path limits (104/108 bytes).
	sockDir, err := os.MkdirTemp("", "hzsock*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })

	sockPath := filepath.Join(sockDir, "host.zap.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("unix domain sockets unavailable: %v", err)
	}
	if uln, ok := ln.(*net.UnixListener); ok {
		uln.SetUnlinkOnClose(false)
	}
	_ = ln.Close()

	info, err := os.Lstat(sockPath)
	if err != nil {
		t.Fatalf("expected stale socket at %q: %v", sockPath, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("expected ModeSocket on %q, got %s", sockPath, info.Mode())
	}

	if err := prepareZAPSocket(sockPath); err != nil {
		t.Fatalf("prepareZAPSocket(%q) error: %v", sockPath, err)
	}
	if _, err := os.Lstat(sockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected stale socket %q to be removed, got err=%v", sockPath, err)
	}
}

func TestPrepareZAPSocketMissingPathCreatesParentDir(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "nested", "zap")
	sockPath := filepath.Join(parent, "host.zap.sock")

	if err := prepareZAPSocket(sockPath); err != nil {
		t.Fatalf("prepareZAPSocket(%q) error: %v", sockPath, err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected parent dir %q to be created: info=%v err=%v", parent, info, err)
	}
}

func TestPrepareZAPSocketIgnoresTCPAndAbstract(t *testing.T) {
	for _, addr := range []string{"", "127.0.0.1:9653", ":9653", "@hanzo-host", "zap://127.0.0.1:9653"} {
		if err := prepareZAPSocket(addr); err != nil {
			t.Errorf("prepareZAPSocket(%q) = %v, want nil", addr, err)
		}
	}
}
