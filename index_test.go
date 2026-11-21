// SPDX-License-Identifier: Apache-2.0 OR MIT

package cloud

import (
	"encoding/json"
	"testing"

	"github.com/zap-proto/zip"
)

func TestIndexListsEnabledSubsystemsInMountOrder(t *testing.T) {
	specs := []MountSpec{
		{Name: "kv", Description: "keys"},
		{Name: "storage", Prefix: "/v1/s3", Description: "objects"},
		{Name: "functions", Description: "code"}, // staged: not enabled below
	}
	cfg := &Config{}

	app := zip.New(zip.Config{})
	mountIndex(app, specs, cfg)

	res, body := get(t, app, "/v1")
	if res.StatusCode != 200 {
		t.Fatalf("GET /v1: status %d: %s", res.StatusCode, body)
	}
	var got Capabilities
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	want := []Capability{
		{Name: "kv", Href: "/v1/kv", Stage: "ga", Description: "keys"},
		{Name: "storage", Href: "/v1/s3", Stage: "ga", Description: "objects"},
	}
	if len(got.Capabilities) != len(want) {
		t.Fatalf("capabilities = %+v, want %+v", got.Capabilities, want)
	}
	for i := range want {
		if got.Capabilities[i] != want[i] {
			t.Errorf("capabilities[%d] = %+v, want %+v", i, got.Capabilities[i], want[i])
		}
	}
}

func TestIndexOmitsWhatIsNotEnabled(t *testing.T) {
	specs := []MountSpec{{Name: "kv"}, {Name: "tasks"}}
	cfg := &Config{Enable: []string{"tasks"}}
	got := capabilities(specs, cfg)
	if len(got.Capabilities) != 1 || got.Capabilities[0].Name != "tasks" {
		t.Fatalf("capabilities = %+v, want only tasks", got.Capabilities)
	}
}
