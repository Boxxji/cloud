package cloud

import (
	"os"
	"testing"
)

func TestLoadConfig_IssuerDerivedFromBrand(t *testing.T) {
	t.Setenv("CLOUD_BRAND", "lux")
	os.Unsetenv("CLOUD_IAM_ISSUER")
	cfg := LoadConfig()
	if cfg.IAMIssuer != "https://lux.id" {
		t.Fatalf("derived issuer = %q, want https://lux.id", cfg.IAMIssuer)
	}
	if cfg.Brand != "lux" {
		t.Fatalf("brand = %q, want lux", cfg.Brand)
	}
}
