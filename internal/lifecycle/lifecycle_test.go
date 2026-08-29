package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wganchor/internal/config"
)

func TestConfigPathForInstance(t *testing.T) {
	if got, want := config.PathForInstance(0), "/etc/wganchor/0.json"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := config.PathForInstance(1), "/etc/wganchor/1.json"; got != want {
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
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// touchInWantsDir simulates `systemctl enable`'s effect: an enablement
// symlink for name under systemdDir/wantsSubdir/. otherEnabledInstanceUnits
// only looks at the file's base name, so a plain empty file stands in
// fine for a real symlink in these fixtures.
func touchInWantsDir(t *testing.T, systemdDir, wantsSubdir string, names ...string) {
	t.Helper()
	dir := filepath.Join(systemdDir, wantsSubdir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	touchFiles(t, dir, names...)
}

func TestOtherEnabledInstanceUnitsExcludesSelf(t *testing.T) {
	dir := t.TempDir()
	touchInWantsDir(t, dir, "multi-user.target.wants", "wganchor-client@0.service")

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
	touchInWantsDir(t, dir, "multi-user.target.wants", "wganchor-client@0.service", "wganchor-client@1.service")

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
	touchInWantsDir(t, dir, "multi-user.target.wants", "wganchor-server@0.service")

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

// TestOtherEnabledInstanceUnitsFindsPerInstanceWantsDir guards the
// widened glob the watch companion unit needs: its [Install] section
// points WantedBy= at the bring-up unit itself rather than
// multi-user.target, so its enablement symlink lands under a
// per-instance wants directory (wganchor-client@0.service.wants/)
// instead of multi-user.target.wants/ — and the bring-up unit's own
// existing location must still be found too.
func TestOtherEnabledInstanceUnitsFindsPerInstanceWantsDir(t *testing.T) {
	dir := t.TempDir()
	touchInWantsDir(t, dir, "multi-user.target.wants", "wganchor-client@0.service")
	touchInWantsDir(t, dir, "wganchor-client@0.service.wants", "wganchor-watch-client@0.service")

	got, err := otherEnabledInstanceUnits(dir, "watch-client", "wganchor-watch-client@1.service")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"wganchor-watch-client@0.service"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}

	// The bring-up unit's own call site must still work unchanged.
	got, err = otherEnabledInstanceUnits(dir, "client", "wganchor-client@1.service")
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"wganchor-client@0.service"}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestOtherEnabledInstanceUnitsWatchPatternDoesNotMatchBringUp guards
// the pattern-collision risk the plan flagged: "wganchor-client@*" must
// never match "wganchor-watch-client@..." units, and vice versa.
func TestOtherEnabledInstanceUnitsWatchPatternDoesNotMatchBringUp(t *testing.T) {
	dir := t.TempDir()
	touchInWantsDir(t, dir, "wganchor-client@0.service.wants", "wganchor-watch-client@0.service")

	got, err := otherEnabledInstanceUnits(dir, "client", "wganchor-client@1.service")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected a watch unit to never match the bring-up unit's pattern, got %v", got)
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
	if err := os.WriteFile(path, []byte(stale), 0o644); err != nil {
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
	if err := os.WriteFile(path, []byte(unitTemplateForRole("server")), 0o644); err != nil {
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

func TestWriteWatchUnitIfChangedWritesWhenMissing(t *testing.T) {
	dir := t.TempDir()
	if err := writeWatchUnitIfChanged(dir, "client"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "wganchor-watch-client@.service"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != watchUnitTemplateForRole("client") {
		t.Fatalf("written content doesn't match the embedded watch template")
	}
}

func TestWriteWatchUnitIfChangedLeavesUpToDateContentAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wganchor-watch-server@.service")
	if err := os.WriteFile(path, []byte(watchUnitTemplateForRole("server")), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := writeWatchUnitIfChanged(dir, "server"); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("expected an already-up-to-date watch template to be left untouched, but it was rewritten")
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
