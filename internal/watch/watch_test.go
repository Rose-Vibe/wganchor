package watch

import (
	"os"
	"path/filepath"
	"testing"
	"wganchor/internal/routing"
)

// TestReconcileOnceRejectsInvalidConfigWithoutReconciling guards the
// blocking issue from the implementation review: config.Load alone
// accepts a semantically-empty config (e.g. relay_ips caught mid-edit,
// or a fresh `install` skeleton), and without a ValidateConfig call
// in between, a self-healing daemon would diff that empty desired state
// against live state and delete every currently-live address/rule for
// the instance. ValidateConfig must reject this *before* any
// Reconcile*Routes call — verified here by the absence of any error
// about a missing/nonexistent interface, which is what a real
// `ip ... show dev <name>` attempt against this test's nonexistent
// interface name would produce if reconcileOnce reached that far.
func TestReconcileOnceRejectsInvalidConfigWithoutReconciling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	// Valid JSON, valid mode, but relay_ips is empty — exactly the shape
	// internal/lifecycle's skeletonConfig writes for a fresh install, and
	// what an editor could leave behind mid-write.
	if err := os.WriteFile(path, []byte(`{"private_key":"x","peer_public_key":"y","peer_endpoint":"1.2.3.4:1","interface_name":"wganchor-nonexistent-test-iface","relay_ips":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := reconcileOnce("client", 0, path)
	if err == nil {
		t.Fatal("expected reconcileOnce to reject an empty relay_ips config, got nil error")
	}
	if got := err.Error(); got != "relay_ips is empty; nothing to relay" {
		t.Fatalf("expected the ValidateConfig error specifically (proving it was rejected before any Reconcile*Routes/runCmd call), got: %v", got)
	}
}

// Captured live against the installed iproute2 build (iproute2-6.1.0) by
// adding then deleting a scratch rule (`ip rule add/del from 203.0.113.1
// table 9999 priority 65000`) while `ip monitor rule` was running.
const (
	monitorAddLine    = "65000:\tfrom 203.0.113.1 lookup 9999"
	monitorDeleteLine = "Deleted 65000:\tfrom 203.0.113.1 lookup 9999"
)

func TestShouldTriggerOnMatchingDeletedRule(t *testing.T) {
	trigger, parseFailed := shouldTrigger(monitorDeleteLine, 9999, 65000)
	if !trigger {
		t.Fatal("expected a deleted rule matching table+priority to trigger")
	}
	if parseFailed {
		t.Fatal("a cleanly-matched line must not report a parse failure")
	}
}

func TestShouldTriggerIgnoresNonMatchingTable(t *testing.T) {
	trigger, parseFailed := shouldTrigger(monitorDeleteLine, 6021, 65000)
	if trigger {
		t.Fatal("must not trigger for a different table, even with a matching priority")
	}
	if parseFailed {
		t.Fatal("a successfully-parsed table mismatch is not a parse failure")
	}
}

func TestShouldTriggerIgnoresNonMatchingPriority(t *testing.T) {
	trigger, parseFailed := shouldTrigger(monitorDeleteLine, 9999, 1)
	if trigger {
		t.Fatal("must not trigger for a different priority, even with a matching table")
	}
	if parseFailed {
		t.Fatal("a deletion that simply isn't ours (wrong priority) is not a parse failure")
	}
}

func TestShouldTriggerIgnoresAddedRule(t *testing.T) {
	trigger, parseFailed := shouldTrigger(monitorAddLine, 9999, 65000)
	if trigger {
		t.Fatal("an added/changed rule (no \"Deleted\" prefix) must never trigger")
	}
	if parseFailed {
		t.Fatal("a non-deletion line is not a parse failure")
	}
}

func TestShouldTriggerIgnoresUnrelatedNonDeletionLines(t *testing.T) {
	for _, line := range []string{"", "some unrelated ip monitor output"} {
		trigger, parseFailed := shouldTrigger(line, 60217, 20217)
		if trigger || parseFailed {
			t.Fatalf("expected silent non-match for %q, got trigger=%v parseFailed=%v", line, trigger, parseFailed)
		}
	}
}

// TestShouldTriggerFlagsUnparsableDeletedLines guards should-fix #4 from
// the implementation review: a "Deleted" line whose priority matches
// ours but whose table can't be determined must be flagged via
// parseFailed (worth logging — it may mean iproute2's line format
// changed) rather than silently treated the same as an unrelated,
// correctly-ignored deletion.
func TestShouldTriggerFlagsUnparsableDeletedLines(t *testing.T) {
	cases := []string{
		"Deleted",
		"Deleted garbage",
		"Deleted 65000:\tfrom 203.0.113.1",        // matching priority, no lookup/table field at all
		"Deleted 65000:\tfrom 203.0.113.1 lookup", // matching priority, dangling "lookup" with no value
	}
	for _, line := range cases {
		trigger, parseFailed := shouldTrigger(line, 9999, 65000)
		if trigger {
			t.Fatalf("must never trigger on an unparsable line, got trigger=true for %q", line)
		}
		if !parseFailed {
			t.Fatalf("expected parseFailed=true for unparsable line %q", line)
		}
	}
}

func TestDescribeChanges(t *testing.T) {
	r := routing.ReconcileResult{
		AddrsAdded:  []string{"203.0.113.20"},
		RoutesAdded: []string{"default"},
		RulesAdded:  []string{"203.0.113.20"},
	}
	got := describeChanges(60217, r)
	want := "added address 203.0.113.20/32, added default route (table 60217), added rule for 203.0.113.20 (table 60217)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
