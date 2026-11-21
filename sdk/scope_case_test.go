package cloud

import "testing"

// The router matches case-insensitively, so every spelling it accepts for a
// subsystem's address lies under that subsystem's prefix, and a sibling that
// merely shares the letters does not.
func TestUnderFoldsCase(t *testing.T) {
	for _, path := range []string{"/v1/exec", "/V1/EXEC", "/V1/Exec/files", "/v1/exec/", "/v1/EXEC/upload"} {
		if !PathUnder(path, "/v1/exec") {
			t.Errorf("under(%q) = false", path)
		}
	}
	for _, path := range []string{"/v1/execute", "/V1/EXECUTOR", "/v1/ex"} {
		if PathUnder(path, "/v1/exec") {
			t.Errorf("under(%q) = true", path)
		}
	}
}
