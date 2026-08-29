package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// everything written to it — used to assert on liveApplyRelay's printed
// deferred-application note, since it (deliberately, matching this
// project's existing print-to-stdout pattern for operational messages)
// writes via fmt.Printf rather than taking an io.Writer parameter.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()

	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestAddRelayIPAppendsWhenAbsent(t *testing.T) {
	got, changed := addRelayIP([]string{"203.0.113.1"}, "203.0.113.2")
	if !changed {
		t.Fatal("expected changed = true when adding a new IP")
	}
	want := []string{"203.0.113.1", "203.0.113.2"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAddRelayIPNoOpWhenAlreadyPresent(t *testing.T) {
	got, changed := addRelayIP([]string{"203.0.113.1", "203.0.113.2"}, "203.0.113.2")
	if changed {
		t.Fatal("expected changed = false when the IP is already present")
	}
	if len(got) != 2 {
		t.Fatalf("expected list to be unchanged, got %v", got)
	}
}

func TestRemoveRelayIPRemovesWhenPresent(t *testing.T) {
	got, changed := removeRelayIP([]string{"203.0.113.1", "203.0.113.2"}, "203.0.113.1")
	if !changed {
		t.Fatal("expected changed = true when removing a present IP")
	}
	if len(got) != 1 || got[0] != "203.0.113.2" {
		t.Fatalf("got %v, want [203.0.113.2]", got)
	}
}

func TestRemoveRelayIPNoOpWhenAbsent(t *testing.T) {
	got, changed := removeRelayIP([]string{"203.0.113.1"}, "203.0.113.2")
	if changed {
		t.Fatal("expected changed = false when the IP is absent")
	}
	if len(got) != 1 || got[0] != "203.0.113.1" {
		t.Fatalf("got %v, want [203.0.113.1] (list preserved on a no-op remove)", got)
	}
}

// TestRemoveRelayIPToEmptyListSucceeds guards the plan's explicit
// non-goal: relay remove itself must not refuse emptying relay_ips to
// zero — that's ValidateConfig's job to catch at bring-up, not remove's.
func TestRemoveRelayIPToEmptyListSucceeds(t *testing.T) {
	got, changed := removeRelayIP([]string{"203.0.113.1"}, "203.0.113.1")
	if !changed {
		t.Fatal("expected changed = true")
	}
	if len(got) != 0 {
		t.Fatalf("expected an empty list, got %v", got)
	}
}

// TestApplyRelayListChangePersistsWhenChanged and
// TestApplyRelayListChangeNoOpWhenUnchanged guard the persist step in
// isolation from precheckRelayCmd's root requirement and
// liveApplyRelay's ip/wg dependency — the exit criterion is "relay
// add/remove persist relay_ips correctly and idempotently (mtime-
// unchanged on a genuine no-op)".
func TestApplyRelayListChangePersistsWhenChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	updated, changed := addRelayIP(cfg.RelayIPs, "203.0.113.9")
	if err := applyRelayListChange(cfg, path, updated, changed); err != nil {
		t.Fatal(err)
	}

	reloaded, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.RelayIPs) != 2 || reloaded.RelayIPs[1] != "203.0.113.9" {
		t.Fatalf("expected the new IP to be persisted, got %v", reloaded.RelayIPs)
	}
}

func TestApplyRelayListChangeNoOpWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// addRelayIP against an IP already present reports changed = false;
	// applyRelayListChange must then leave the file untouched.
	updated, changed := addRelayIP(cfg.RelayIPs, cfg.RelayIPs[0])
	if changed {
		t.Fatal("expected changed = false when the IP is already present")
	}
	if err := applyRelayListChange(cfg, path, updated, changed); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("expected a genuine no-op change to leave the file untouched, but it was rewritten")
	}
}

// TestApplyRelayListChangeNoOpForRemoveWhenUnchanged is
// TestApplyRelayListChangeNoOpWhenUnchanged's remove-side counterpart
// (should-fix from implementation review: the add-side no-op was
// covered, but not remove's) — a remove of an IP that isn't present must
// leave the file untouched too.
func TestApplyRelayListChangeNoOpForRemoveWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	updated, changed := removeRelayIP(cfg.RelayIPs, "203.0.113.250") // not present in newTestConfig()
	if changed {
		t.Fatal("expected changed = false when the IP is absent")
	}
	if err := applyRelayListChange(cfg, path, updated, changed); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("expected a genuine no-op remove to leave the file untouched, but it was rewritten")
	}
}

// TestLiveApplyRelayDeferredWhenInterfaceAbsent guards the "interface
// doesn't exist yet" path: liveApplyRelay must not error, just print a
// deferred-application note naming the interface it looked for (should-
// fix from implementation review: the note used to omit the name
// entirely, making a wrong-name/wrong-instance mistake undiagnosable).
// Uses an interface name guaranteed not to exist in any test environment.
func TestLiveApplyRelayDeferredWhenInterfaceAbsent(t *testing.T) {
	cfg := newTestConfig()
	cfg.InterfaceName = "wganchor-test-does-not-exist-9999"
	var err error
	out := captureStdout(t, func() {
		err = liveApplyRelay("client", cfg, 0)
	})
	if err != nil {
		t.Fatalf("expected no error when the interface doesn't exist yet, got %v", err)
	}
	if !strings.Contains(out, "wganchor-test-does-not-exist-9999") {
		t.Fatalf("expected the deferred note to name the interface it looked for, got %q", out)
	}
}

// TestLiveApplyRelayResolvesBlankDefaultsBeforeExistenceCheck guards the
// fix that came out of implementation review: BOTH a blank InterfaceName
// and a zero ListenPort must resolve to their per-instance defaults
// (resolveRuntimeDefaults) *before* interfaceExists is checked / before
// ConfigureInterface could ever be reached — not fall through to
// interfaceExists("") (which would spuriously report "not up yet" even
// when a live interface exists under its real default name) and not
// reach ConfigureInterface with a zero listen port (which would rebind
// WireGuard to a random ephemeral port). Both fields are left blank/zero
// together here, deliberately, since a hand-edited config omitting one
// plausibly omits the other too, and that's exactly the population
// implementation review flagged as under-tested. This test can't spin up
// a real interface, so it only exercises the deferred-note path — the
// resolution itself is asserted directly and unconditionally by
// TestResolveRuntimeDefaultsFillsBlankAndZero (config_test.go).
func TestLiveApplyRelayResolvesBlankDefaultsBeforeExistenceCheck(t *testing.T) {
	const instance = 4321 // an instance number this dev/test environment has never brought up
	if interfaceExists(defaultInterfaceName(instance)) {
		t.Skipf("unexpected: %s already exists in this environment, can't use it as a known-absent fixture", defaultInterfaceName(instance))
	}
	cfg := newTestConfig()
	cfg.InterfaceName = "" // must resolve to defaultInterfaceName(instance), not interfaceExists("")
	cfg.ListenPort = 0     // must resolve to defaultListenPort(instance), never reach ConfigureInterface as 0
	var err error
	out := captureStdout(t, func() {
		err = liveApplyRelay("server", cfg, instance)
	})
	if err != nil {
		t.Fatalf("expected no error (deferred note, not a live-apply attempt against a bogus name/port), got %v", err)
	}
	if !strings.Contains(out, defaultInterfaceName(instance)) {
		t.Fatalf("expected the deferred note to name the resolved default interface, got %q", out)
	}
}
