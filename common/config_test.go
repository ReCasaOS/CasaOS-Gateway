package common

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigGatewayAddress(t *testing.T) {
	load := func(t *testing.T, ini string) string {
		t.Helper()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "gateway.ini"), []byte(ini), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CASAOS_CONFIG_PATH", dir)
		config, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig() = %v", err)
		}
		return config.GetString(ConfigKeyGatewayAddress)
	}

	// Every existing install has no address key: it must keep binding all interfaces.
	if got := load(t, "[gateway]\nport=80\n"); got != "" {
		t.Fatalf("address without key = %q, want empty", got)
	}
	if got := load(t, "[gateway]\nport=80\naddress=10.1.1.5\n"); got != "10.1.1.5" {
		t.Fatalf("address = %q, want 10.1.1.5", got)
	}
}
