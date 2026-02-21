package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPolicy_Success(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dp.yaml")

	content := `
version: 1
domains:
  cost:
    enabled: true
rules:
  EC2_LOW_CPU:
    enabled: false
    severity: HIGH
`

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadPolicy(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Version != 1 {
		t.Fatalf("expected version 1")
	}

	if !cfg.Domains["cost"].Enabled {
		t.Fatalf("expected cost domain enabled")
	}

	rc := cfg.Rules["EC2_LOW_CPU"]

	if rc.Enabled == nil || *rc.Enabled != false {
		t.Fatalf("expected EC2_LOW_CPU enabled=false")
	}

	if rc.Severity != "HIGH" {
		t.Fatalf("expected severity HIGH")
	}
}

func TestLoadPolicy_InvalidVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dp.yaml")

	content := `
version: 2
`

	os.WriteFile(path, []byte(content), 0o644)

	_, err := LoadPolicy(path)
	if err == nil {
		t.Fatalf("expected error for invalid version")
	}
}

func TestLoadPolicy_FileNotFound(t *testing.T) {
	_, err := LoadPolicy("nonexistent.yaml")
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}