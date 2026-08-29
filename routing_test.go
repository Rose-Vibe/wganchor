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
