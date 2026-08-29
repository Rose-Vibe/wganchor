package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistConfigRoundTripsAndKeepsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{PrivateKey: "abc", PeerPublicKey: "def", RelayIPs: []string{"203.0.113.20"}}
	if err := persistConfig(cfg, path); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected mode 0600, got %04o", perm)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error loading persisted config: %v", err)
	}
	if got.PrivateKey != "abc" || got.PeerPublicKey != "def" {
		t.Fatalf("round-tripped config mismatch: %+v", got)
	}

	// No leftover temp file in the same directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "0.json" {
		t.Fatalf("expected only 0.json in %s, got %v", dir, entries)
	}
}
