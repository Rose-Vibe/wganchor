package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigPathForInstance(t *testing.T) {
	if got, want := configPathForInstance(0), "/etc/wganchor/0.json"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := configPathForInstance(1), "/etc/wganchor/1.json"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestSkeletonConfigFillsConcreteDefaults(t *testing.T) {
	cfg := skeletonConfig(0, "somekey")
	if cfg.PrivateKey != "somekey" {
		t.Fatalf("expected private key to be set, got %q", cfg.PrivateKey)
	}
	if cfg.InterfaceName != "wganchor0" {
		t.Fatalf("expected interface_name=wganchor0, got %q", cfg.InterfaceName)
	}
	if cfg.ListenPort != 60217 {
		t.Fatalf("expected listen_port=60217, got %d", cfg.ListenPort)
	}
	if cfg.PeerPublicKey != "" || cfg.PeerEndpoint != "" || len(cfg.RelayIPs) != 0 {
		t.Fatalf("expected peer info and relay_ips left blank for the operator, got %+v", cfg)
	}
}

func TestSkeletonConfigDistinctPerInstance(t *testing.T) {
	cfg0 := skeletonConfig(0, "a")
	cfg1 := skeletonConfig(1, "b")
	if cfg0.InterfaceName == cfg1.InterfaceName {
		t.Fatal("expected distinct interface names per instance")
	}
	if cfg0.ListenPort == cfg1.ListenPort {
		t.Fatal("expected distinct listen ports per instance")
	}
}

func touchFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOtherEnabledInstanceUnitsExcludesSelf(t *testing.T) {
	dir := t.TempDir()
	touchFiles(t, dir, "wganchor-client@0.service")

	got, err := otherEnabledInstanceUnits(dir, "client", "wganchor-client@0.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no other enabled client instances, got %v", got)
	}
}

func TestOtherEnabledInstanceUnitsFindsAnotherInstance(t *testing.T) {
	dir := t.TempDir()
	touchFiles(t, dir, "wganchor-client@0.service", "wganchor-client@1.service")

	got, err := otherEnabledInstanceUnits(dir, "client", "wganchor-client@1.service")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"wganchor-client@0.service"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestOtherEnabledInstanceUnitsIgnoresOtherRole(t *testing.T) {
	dir := t.TempDir()
	touchFiles(t, dir, "wganchor-server@0.service")

	got, err := otherEnabledInstanceUnits(dir, "client", "wganchor-client@0.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected server-role units to be ignored when checking client, got %v", got)
	}
}

func TestOtherEnabledInstanceUnitsEmptyDir(t *testing.T) {
	dir := t.TempDir()
	got, err := otherEnabledInstanceUnits(dir, "client", "wganchor-client@0.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no matches in an empty directory, got %v", got)
	}
}

func TestPrecheckLifecycleFailsWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this process is root; can't exercise the non-root branch")
	}
	err := precheckLifecycle()
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("expected a must-be-root error, got %v", err)
	}
}

func TestPrecheckLifecycleFailsWithoutSystemctlOnPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to isolate the systemctl-missing case from the non-root case")
	}
	t.Setenv("PATH", t.TempDir()) // a directory with nothing in it
	err := precheckLifecycle()
	if err == nil || !strings.Contains(err.Error(), "systemctl") {
		t.Fatalf("expected a systemctl-not-found error, got %v", err)
	}
}

func TestWriteUnitIfChangedWritesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	if err := writeUnitIfChanged(dir, "client"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "wganchor-client@.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != unitTemplateForRole("client") {
		t.Fatalf("written content doesn't match the embedded template")
	}
}

func TestWriteUnitIfChangedRewritesStaleContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wganchor-server@.service")
	stale := "[Service]\nType=simple\n"
	if err := os.WriteFile(path, []byte(stale), 0644); err != nil {
		t.Fatal(err)
	}

	if err := writeUnitIfChanged(dir, "server"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != unitTemplateForRole("server") {
		t.Fatalf("expected the stale Type=simple template to be replaced with the current embedded one, got:\n%s", got)
	}
}

func TestWriteUnitIfChangedLeavesUpToDateContentAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wganchor-server@.service")
	if err := os.WriteFile(path, []byte(unitTemplateForRole("server")), 0644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := writeUnitIfChanged(dir, "server"); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("expected an already-up-to-date template to be left untouched, but it was rewritten")
	}
}

func TestIsUnitNotInstalledOutput(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"unit does not exist", "Unit wganchor-client@5.service does not exist, proceeding anyway.", true},
		{"no such file", "Failed to disable unit: No such file or directory", true},
		{"real failure", "Job for wganchor-client@0.service failed because the control process exited with error code.", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := isUnitNotInstalledOutput(c.output); got != c.want {
			t.Errorf("%s: isUnitNotInstalledOutput(%q) = %v, want %v", c.name, c.output, got, c.want)
		}
	}
}
