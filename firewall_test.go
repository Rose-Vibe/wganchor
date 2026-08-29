package main

import "testing"

// Captured live against the installed nftables build (nftables v1.0.9)
// from the hand-applied stopgap firewall this sprint, plus synthesized
// instance-1/instance-10 lines to exercise the substring-collision case
// the plan calls out explicitly.
const sampleChainListing = `table ip wganchor {
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		iifname "wganchor0" ct state established,related accept comment "wganchor-instance-0" # handle 6
		iifname "wganchor0" tcp dport @wganchor0_tcp accept comment "wganchor-instance-0" # handle 7
		iifname "wganchor0" udp dport @wganchor0_udp accept comment "wganchor-instance-0" # handle 8
		iifname "wganchor0" counter packets 534 bytes 38295 drop comment "wganchor-instance-0" # handle 9
		iifname "wganchor1" ct state established,related accept comment "wganchor-instance-1" # handle 10
		iifname "wganchor1" counter drop comment "wganchor-instance-1" # handle 11
		iifname "wganchor10" ct state established,related accept comment "wganchor-instance-10" # handle 12
		iifname "wganchor10" tcp dport @wganchor10_tcp accept comment "wganchor-instance-10" # handle 13
		iifname "wganchor10" udp dport @wganchor10_udp accept comment "wganchor-instance-10" # handle 14
		iifname "wganchor10" counter drop comment "wganchor-instance-10" # handle 15
	}
}`

func TestInstanceCommentAndSetName(t *testing.T) {
	if got, want := instanceComment(0), "wganchor-instance-0"; got != want {
		t.Fatalf("instanceComment(0) = %q, want %q", got, want)
	}
	if got, want := quotedInstanceComment(0), `comment "wganchor-instance-0"`; got != want {
		t.Fatalf("quotedInstanceComment(0) = %q, want %q", got, want)
	}
	if got, want := instanceSetName(0, "tcp"), "wganchor0_tcp"; got != want {
		t.Fatalf("instanceSetName(0, tcp) = %q, want %q", got, want)
	}
}

// TestExistingInstanceBaseRuleKindsExactMatchNotSubstring is the plan's
// required exit-criterion test: "wganchor-instance-1" is a substring of
// "wganchor-instance-10", so a naive strings.Contains(line,
// "wganchor-instance-1") would incorrectly count instance 10's rules
// as instance 1's.
func TestExistingInstanceBaseRuleKindsExactMatchNotSubstring(t *testing.T) {
	got := existingInstanceBaseRuleKinds(sampleChainListing, 1, "wganchor1")
	want := map[string]bool{"established": true, "drop": true}
	if len(got) != len(want) {
		t.Fatalf("instance 1: got %v, want exactly %v (must not pick up instance 10's tcp/udp rules)", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Fatalf("instance 1: missing expected kind %q in %v", k, got)
		}
	}
}

func TestExistingInstanceBaseRuleKindsAllFourPresent(t *testing.T) {
	got := existingInstanceBaseRuleKinds(sampleChainListing, 0, "wganchor0")
	for _, kind := range []string{"established", "tcp", "udp", "drop"} {
		if !got[kind] {
			t.Fatalf("instance 0: expected kind %q present, got %v", kind, got)
		}
	}
}

func TestExistingInstanceBaseRuleKindsAbsentInstance(t *testing.T) {
	got := existingInstanceBaseRuleKinds(sampleChainListing, 99, "wganchor99")
	if len(got) != 0 {
		t.Fatalf("expected no kinds for an instance with no rules, got %v", got)
	}
}

// TestExistingInstanceBaseRuleKindsIgnoresStaleIifname guards B2 from the
// implementation review: instance 0's rules in sampleChainListing are all
// bound to iifname "wganchor0". If the operator renamed the interface to
// "wganchor0-new", none of those rules should count as "present" for the
// new name — otherwise ensureInstanceBaseRules would think the new
// interface is already fully filtered when it has no rules at all.
func TestExistingInstanceBaseRuleKindsIgnoresStaleIifname(t *testing.T) {
	got := existingInstanceBaseRuleKinds(sampleChainListing, 0, "wganchor0-new")
	if len(got) != 0 {
		t.Fatalf("expected no kinds to match a renamed interface, got %v", got)
	}
}

// TestStaleRuleHandlesForInstance guards the other half of B2: the
// handles of instance 0's rules (bound to the old iifname "wganchor0")
// must be found so ensureInstanceBaseRules can delete them, and instance
// 1/10's handles must never be included.
func TestStaleRuleHandlesForInstance(t *testing.T) {
	got := staleRuleHandlesForInstance(sampleChainListing, 0, "wganchor0-new")
	want := []int{6, 7, 8, 9}
	if len(got) != len(want) {
		t.Fatalf("stale handles = %v, want %v", got, want)
	}
	for i, h := range want {
		if got[i] != h {
			t.Fatalf("stale handles = %v, want %v", got, want)
		}
	}
}

// TestStaleRuleHandlesForInstanceNoneWhenNameMatches confirms the
// no-op case: once name matches the live rules, nothing is "stale".
func TestStaleRuleHandlesForInstanceNoneWhenNameMatches(t *testing.T) {
	if got := staleRuleHandlesForInstance(sampleChainListing, 0, "wganchor0"); len(got) != 0 {
		t.Fatalf("expected no stale handles when the name matches, got %v", got)
	}
}

// TestRuleHandlesForInstanceExactMatch guards the same substring trap
// for disableInstanceFirewall's handle collection: instance 1's handles
// must never include instance 10's.
func TestRuleHandlesForInstanceExactMatch(t *testing.T) {
	got := ruleHandlesForInstance(sampleChainListing, 1)
	want := []int{10, 11}
	if len(got) != len(want) {
		t.Fatalf("instance 1 handles = %v, want %v", got, want)
	}
	for i, h := range want {
		if got[i] != h {
			t.Fatalf("instance 1 handles = %v, want %v", got, want)
		}
	}
}

func TestRuleHandlesForInstance10(t *testing.T) {
	got := ruleHandlesForInstance(sampleChainListing, 10)
	want := []int{12, 13, 14, 15}
	if len(got) != len(want) {
		t.Fatalf("instance 10 handles = %v, want %v", got, want)
	}
	for i, h := range want {
		if got[i] != h {
			t.Fatalf("instance 10 handles = %v, want %v", got, want)
		}
	}
}

func TestAnyOtherInstanceRuleRemains(t *testing.T) {
	if !anyOtherInstanceRuleRemains(sampleChainListing, 0) {
		t.Fatal("expected instance 1/10's rules to count as \"other\" when excluding instance 0")
	}
	// Excluding all three present instances individually should still
	// find the others.
	if !anyOtherInstanceRuleRemains(sampleChainListing, 1) {
		t.Fatal("expected instance 0/10's rules to count as \"other\" when excluding instance 1")
	}
}

func TestAnyOtherInstanceRuleRemainsNoneLeft(t *testing.T) {
	singleInstance := `table ip wganchor {
	chain input { # handle 1
		type filter hook input priority filter; policy accept;
		iifname "wganchor0" ct state established,related accept comment "wganchor-instance-0" # handle 6
		iifname "wganchor0" counter drop comment "wganchor-instance-0" # handle 9
	}
}`
	if anyOtherInstanceRuleRemains(singleInstance, 0) {
		t.Fatal("expected no other instance to remain when only instance 0's rules exist")
	}
}

func TestParsePortSpecValid(t *testing.T) {
	cases := []struct {
		spec      string
		wantPort  int
		wantProto string
	}{
		{"8080/tcp", 8080, "tcp"},
		{"53/udp", 53, "udp"},
		{"1/tcp", 1, "tcp"},
		{"65535/udp", 65535, "udp"},
	}
	for _, c := range cases {
		port, proto, err := parsePortSpec(c.spec)
		if err != nil {
			t.Fatalf("parsePortSpec(%q): unexpected error: %v", c.spec, err)
		}
		if port != c.wantPort || proto != c.wantProto {
			t.Fatalf("parsePortSpec(%q) = (%d, %q), want (%d, %q)", c.spec, port, proto, c.wantPort, c.wantProto)
		}
	}
}

func TestParsePortSpecInvalid(t *testing.T) {
	for _, spec := range []string{
		"", "8080", "8080/", "/tcp", "8080/sctp", "0/tcp", "65536/tcp", "-1/tcp", "abc/tcp", "8080/tcp/extra",
	} {
		if _, _, err := parsePortSpec(spec); err == nil {
			t.Errorf("parsePortSpec(%q): expected an error, got nil", spec)
		}
	}
}

func TestParseSetElementsEmpty(t *testing.T) {
	listing := "table ip wganchor {\n\tset wganchor0_tcp {\n\t\ttype inet_service\n\t}\n}"
	got := parseSetElements(listing)
	if len(got) != 0 {
		t.Fatalf("expected no elements for an empty set, got %v", got)
	}
}

func TestParseSetElementsMultiple(t *testing.T) {
	listing := "table ip wganchor {\n\tset wganchor0_tcp {\n\t\ttype inet_service\n\t\telements = { 22, 80, 443 }\n\t}\n}"
	got := parseSetElements(listing)
	want := []int{22, 80, 443}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, v := range want {
		if got[i] != v {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestAddPortSpecAppendsWhenAbsent(t *testing.T) {
	got, changed := addPortSpec([]string{"22/tcp"}, "8080/tcp")
	if !changed {
		t.Fatal("expected changed = true when adding a new spec")
	}
	want := []string{"22/tcp", "8080/tcp"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAddPortSpecNoOpWhenAlreadyPresent(t *testing.T) {
	got, changed := addPortSpec([]string{"22/tcp", "8080/tcp"}, "8080/tcp")
	if changed {
		t.Fatal("expected changed = false when the spec is already present")
	}
	if len(got) != 2 {
		t.Fatalf("expected list to be unchanged, got %v", got)
	}
}

func TestRemovePortSpecRemovesWhenPresent(t *testing.T) {
	got, changed := removePortSpec([]string{"22/tcp", "8080/tcp"}, "22/tcp")
	if !changed {
		t.Fatal("expected changed = true when removing a present spec")
	}
	if len(got) != 1 || got[0] != "8080/tcp" {
		t.Fatalf("got %v, want [8080/tcp]", got)
	}
}

func TestRemovePortSpecNoOpWhenAbsent(t *testing.T) {
	got, changed := removePortSpec([]string{"22/tcp"}, "8080/tcp")
	if changed {
		t.Fatal("expected changed = false when the spec is absent")
	}
	if len(got) != 1 || got[0] != "22/tcp" {
		t.Fatalf("got %v, want [22/tcp] (list preserved, this is the disable/enable round-trip's list-preservation guarantee)", got)
	}
}

func TestIsNftAbsentOutput(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"missing element", "Error: Could not process rule: No such file or directory\ndelete element ip wganchor wganchor0_tcp { 9999 }", true},
		{"missing table", "Error: No such file or directory; did you mean table 'wganchor' in family ip?", true},
		{"set still referenced", "Error: Could not process rule: Device or resource busy\ndelete set ip wganchor wganchor0_tcp", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		if got := isNftAbsentOutput(c.output); got != c.want {
			t.Errorf("%s: isNftAbsentOutput(%q) = %v, want %v", c.name, c.output, got, c.want)
		}
	}
}
