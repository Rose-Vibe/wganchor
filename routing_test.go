package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestTableAndPriorityForInstanceAreDistinctAndMatchPoC(t *testing.T) {
	if got := tableForInstance(0); got != 60217 {
		t.Fatalf("table for instance 0 = %d, want 60217 (the value validated in the bootstrap PoC)", got)
	}
	if got := priorityForInstance(0); got != 20217 {
		t.Fatalf("priority for instance 0 = %d, want 20217 (the value validated in the bootstrap PoC)", got)
	}
	if tableForInstance(0) == tableForInstance(1) {
		t.Fatal("expected distinct tables for instance 0 and 1")
	}
	if priorityForInstance(0) == priorityForInstance(1) {
		t.Fatal("expected distinct priorities for instance 0 and 1")
	}
}

func TestDiffRelayIPsAddAndRemove(t *testing.T) {
	desired := []string{"10.0.0.1", "10.0.0.2"}
	current := []string{"10.0.0.2", "10.0.0.3"}

	toAdd, toRemove := diffRelayIPs(desired, current)
	if !reflect.DeepEqual(toAdd, []string{"10.0.0.1"}) {
		t.Fatalf("toAdd = %v, want [10.0.0.1]", toAdd)
	}
	if !reflect.DeepEqual(toRemove, []string{"10.0.0.3"}) {
		t.Fatalf("toRemove = %v, want [10.0.0.3]", toRemove)
	}
}

func TestDiffRelayIPsNoChange(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2"}
	toAdd, toRemove := diffRelayIPs(ips, ips)
	if len(toAdd) != 0 || len(toRemove) != 0 {
		t.Fatalf("expected no diff for identical lists, got toAdd=%v toRemove=%v", toAdd, toRemove)
	}
}

func TestDiffRelayIPsMultipleEntries(t *testing.T) {
	desired := []string{"203.0.113.20", "108.61.192.115", "108.61.192.116"}
	current := []string{"203.0.113.20"}

	toAdd, toRemove := diffRelayIPs(desired, current)
	want := []string{"108.61.192.115", "108.61.192.116"}
	if !reflect.DeepEqual(toAdd, want) {
		t.Fatalf("toAdd = %v, want %v", toAdd, want)
	}
	if len(toRemove) != 0 {
		t.Fatalf("expected no removals, got %v", toRemove)
	}
}

func TestParseRouteShowHostRoutes(t *testing.T) {
	output := "203.0.113.20/32 scope link \ndefault via 10.0.0.1 dev wganchor0 \n108.61.192.115/32 scope link "
	got := parseRouteShowHostRoutes(output)
	want := []string{"203.0.113.20", "108.61.192.115"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseAddrShowHostIPs(t *testing.T) {
	output := `3: wganchor0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 203.0.113.20/32 scope global wganchor0
       valid_lft forever preferred_lft forever
    inet 108.61.192.115/32 scope global wganchor0
       valid_lft forever preferred_lft forever`
	got := parseAddrShowHostIPs(output)
	want := []string{"203.0.113.20", "108.61.192.115"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseIPRuleShowForTable(t *testing.T) {
	output := "0:\tfrom all lookup local\n" +
		"20217:\tfrom 203.0.113.20 lookup 60217\n" +
		"20217:\tfrom 108.61.192.115 lookup 60217\n" +
		"20218:\tfrom all lookup 60217\n" +
		"5270:\tfrom all lookup 52\n" +
		"32766:\tfrom all lookup main\n"
	got := parseIPRuleShowForTable(output, 60217)
	want := []string{"203.0.113.20", "108.61.192.115"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}

	// A table number that's a substring of another (e.g. 6021 vs 60217)
	// must not false-match.
	if got := parseIPRuleShowForTable(output, 6021); len(got) != 0 {
		t.Fatalf("expected no match for table 6021, got %v", got)
	}
}

func TestIPRuleSourceToken(t *testing.T) {
	if got := ipRuleSourceToken("203.0.113.20"); got != "203.0.113.20" {
		t.Fatalf("bare IP: got %q", got)
	}
	if got := ipRuleSourceToken("203.0.113.20/32"); got != "203.0.113.20/32" {
		t.Fatalf("IP/prefix: got %q", got)
	}
	if got := ipRuleSourceToken("all"); got != "" {
		t.Fatalf("wildcard \"all\" must be rejected, got %q", got)
	}
}

// TestIsFibTableMissingOutput guards a real bug found live: a policy
// routing table that has never had a route added to it doesn't "exist"
// as far as the kernel's FIB is concerned, so `ip route show table <N>`
// exits non-zero with this exact message for a genuinely brand-new
// instance's very first bring-up — that must be treated as "no default
// route present yet", not propagated as a hard failure.
func TestIsFibTableMissingOutput(t *testing.T) {
	if !isFibTableMissingOutput("ip route show table 60312: exit status 2: Error: ipv4: FIB table does not exist.\nDump terminated") {
		t.Fatal("expected the real captured FIB-table-missing error to match")
	}
	if isFibTableMissingOutput("Error: Network is unreachable") {
		t.Fatal("must not match an unrelated error")
	}
	if isFibTableMissingOutput("") {
		t.Fatal("empty output must not match")
	}
}

func TestBuildReconcileResult(t *testing.T) {
	r := buildReconcileResult(
		[]string{"203.0.113.20"}, nil,
		nil, []string{"108.61.192.115"},
		[]string{"203.0.113.20"}, nil,
	)
	if !r.Changed() {
		t.Fatal("expected Changed() == true when any slice is non-empty")
	}
	if !reflect.DeepEqual(r.AddrsAdded, []string{"203.0.113.20"}) {
		t.Fatalf("AddrsAdded = %v", r.AddrsAdded)
	}
	if !reflect.DeepEqual(r.RoutesRemoved, []string{"108.61.192.115"}) {
		t.Fatalf("RoutesRemoved = %v", r.RoutesRemoved)
	}
	if !reflect.DeepEqual(r.RulesAdded, []string{"203.0.113.20"}) {
		t.Fatalf("RulesAdded = %v", r.RulesAdded)
	}

	empty := buildReconcileResult(nil, nil, nil, nil, nil, nil)
	if empty.Changed() {
		t.Fatal("expected Changed() == false when every slice is empty")
	}
}

func TestHasDefaultRoute(t *testing.T) {
	present := "default dev wganchor0 scope link \n203.0.113.20 via 10.0.0.1 dev wganchor0 table 60217 \n"
	if !hasDefaultRoute(present, "wganchor0") {
		t.Fatal("expected default route on wganchor0 to be found")
	}

	wrongDev := "default dev wganchor1 scope link \n"
	if hasDefaultRoute(wrongDev, "wganchor0") {
		t.Fatal("must not match a default route on a different device")
	}

	missing := "203.0.113.20 via 10.0.0.1 dev wganchor0 table 60217 \n"
	if hasDefaultRoute(missing, "wganchor0") {
		t.Fatal("expected no default route to be found")
	}
}

func TestIPForwardEnabled(t *testing.T) {
	dir := t.TempDir()

	enabled := filepath.Join(dir, "enabled")
	if err := os.WriteFile(enabled, []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if ok, err := ipForwardEnabled(enabled); err != nil || !ok {
		t.Fatalf("expected enabled=true, got ok=%v err=%v", ok, err)
	}

	disabled := filepath.Join(dir, "disabled")
	if err := os.WriteFile(disabled, []byte("0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if ok, err := ipForwardEnabled(disabled); err != nil || ok {
		t.Fatalf("expected enabled=false, got ok=%v err=%v", ok, err)
	}
}
