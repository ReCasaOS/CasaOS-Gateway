package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ReCasaOS/CasaOS-Common/utils/constants"
)

func TestGatewayConfigFilePath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CASAOS_CONFIG_PATH", dir)
	got := GatewayConfigFilePath()
	want := filepath.Join(dir, "gateway.ini")
	if got != want {
		t.Fatalf("GatewayConfigFilePath() = %q, want %q", got, want)
	}
}

func TestGatewayConfigFilePathUnset(t *testing.T) {
	t.Setenv("CASAOS_CONFIG_PATH", "placeholder")
	if err := os.Unsetenv("CASAOS_CONFIG_PATH"); err != nil {
		t.Fatal(err)
	}
	got := GatewayConfigFilePath()
	want := filepath.Join(constants.DefaultConfigPath, "gateway.ini")
	if got != want {
		t.Fatalf("unset = %q, want %q", got, want)
	}
}

func TestGatewayConfigFilePathEmpty(t *testing.T) {
	t.Setenv("CASAOS_CONFIG_PATH", "")
	got := GatewayConfigFilePath()
	want := filepath.Join(constants.DefaultConfigPath, "gateway.ini")
	if got != want {
		t.Fatalf("empty = %q, want %q", got, want)
	}
}

func TestEnsureGatewayConfigCreatesUnderEnv(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "nested", "etc")
	t.Setenv("CASAOS_CONFIG_PATH", dir)
	const sample = "[gateway]\nport=8081\n"
	if err := EnsureGatewayConfig(sample); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gateway.ini")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != sample {
		t.Fatalf("wrote %q, want %q", body, sample)
	}
}

func TestEnsureGatewayConfigDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CASAOS_CONFIG_PATH", dir)
	path := filepath.Join(dir, "gateway.ini")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureGatewayConfig("[gateway]\nport=1\n"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "keep me" {
		t.Fatalf("overwrote: %q", body)
	}
}
