package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstanceDefaultsAreDistinct(t *testing.T) {
	iface0 := defaultInterfaceName(0)
	iface1 := defaultInterfaceName(1)
	port0 := defaultListenPort(0)
	port1 := defaultListenPort(1)

	if iface0 == iface1 {
		t.Fatalf("expected distinct interface names, got %q for both instance 0 and 1", iface0)
	}
	if port0 == port1 {
		t.Fatalf("expected distinct listen ports, got %d for both instance 0 and 1", port0)
	}
	if iface0 != "wganchor0" || iface1 != "wganchor1" {
		t.Fatalf("unexpected interface names: instance 0 = %q, instance 1 = %q", iface0, iface1)
	}
	if port0 != 60217 || port1 != 60218 {
		t.Fatalf("unexpected listen ports: instance 0 = %d, instance 1 = %d", port0, port1)
	}
}

// TestResolveRuntimeDefaultsFillsBlankAndZero guards the fix that came
// out of relay-management's implementation review: liveApplyRelay
// (relay.go) must resolve BOTH the interface name and the listen port
// via this function before touching live state, not just the interface
// name — a config that omits listen_port is legal (wireguard.md) and,
// if the zero value reached ConfigureInterface directly, would silently
// rebind WireGuard to a random ephemeral port instead of the documented
// default.
func TestResolveRuntimeDefaultsFillsBlankAndZero(t *testing.T) {
	cfg := &Config{}
	name, port := resolveRuntimeDefaults(cfg, 4321)
	if name != "wganchor4321" {
		t.Fatalf("expected the default interface name for a blank interface_name, got %q", name)
	}
	if port != 64538 {
		t.Fatalf("expected the default listen port (60217+4321) for a zero listen_port, got %d", port)
	}
}

func TestResolveRuntimeDefaultsPreservesExplicitValues(t *testing.T) {
	cfg := &Config{InterfaceName: "custom0", ListenPort: 9999}
	name, port := resolveRuntimeDefaults(cfg, 0)
	if name != "custom0" || port != 9999 {
		t.Fatalf("expected explicit config values to be preserved, got (%q, %d)", name, port)
	}
}

func TestResolveConfigPathExplicitMustExist(t *testing.T) {
	_, _, err := resolveConfigPath(filepath.Join(t.TempDir(), "missing.json"), 0)
	if err == nil {
		t.Fatal("expected an error for a nonexistent explicit --config path")
	}
}

func TestResolveConfigPathExplicitFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}

	got, _, err := resolveConfigPath(path, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != path {
		t.Fatalf("expected %q, got %q", path, got)
	}
}

func TestResolveConfigPathNoneFoundReturnsErrAndChecked(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, checked0, err := resolveConfigPath("", 0)
	if err == nil {
		t.Fatal("expected errNoConfigFound when nothing exists")
	}
	if len(checked0) == 0 {
		t.Fatal("expected the checked path list to be non-empty even on failure")
	}

	_, checked1, err := resolveConfigPath("", 1)
	if err == nil {
		t.Fatal("expected errNoConfigFound when nothing exists")
	}
	for i := range checked0 {
		if checked0[i] == checked1[i] {
			t.Fatalf("expected instance 0 and 1 to check distinct paths, both included %q", checked0[i])
		}
	}
}

func TestResolveConfigPathRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := resolveConfigPath(dir, 0); err == nil {
		t.Fatal("expected an error when the explicit --config path is a directory")
	}
}

func TestValidateInstanceRejectsOutOfRange(t *testing.T) {
	if err := validateInstance(-1); err == nil {
		t.Fatal("expected an error for a negative instance")
	}
	if err := validateInstance(maxInstance + 1); err == nil {
		t.Fatal("expected an error for an instance pushing listen_port past 65535")
	}
	if err := validateInstance(0); err != nil {
		t.Fatalf("unexpected error for instance 0: %v", err)
	}
	if err := validateInstance(maxInstance); err != nil {
		t.Fatalf("unexpected error for maxInstance: %v", err)
	}
}

func TestLoadConfigRejectsWrongMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected loadConfig to refuse a 0644 config file")
	}
}

func TestLoadConfigParsesSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	body := `{
		"private_key": "abc",
		"peer_public_key": "def",
		"peer_endpoint": "203.0.113.10:60217",
		"listen_port": 60217,
		"interface_name": "wganchor0",
		"relay_ips": ["203.0.113.20"],
		"persistent_keepalive": 25
	}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PrivateKey != "abc" || cfg.PeerPublicKey != "def" {
		t.Fatalf("unexpected parsed keys: %+v", cfg)
	}
	if len(cfg.RelayIPs) != 1 || cfg.RelayIPs[0] != "203.0.113.20" {
		t.Fatalf("unexpected relay_ips: %+v", cfg.RelayIPs)
	}
}

func TestRedactedMasksPrivateKey(t *testing.T) {
	cfg := Config{PrivateKey: "supersecret"}
	redacted := cfg.Redacted()
	if redacted.PrivateKey == "supersecret" {
		t.Fatal("expected Redacted() to mask the private key")
	}
	if cfg.PrivateKey != "supersecret" {
		t.Fatal("Redacted() must not mutate the original Config")
	}
}
