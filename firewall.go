package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// firewallTable is the single, dedicated nftables table this tool ever
// creates or touches — never any table Docker, Tailscale, or anything
// else owns (see docs/arch/firewall.md's coexistence design).
const firewallTable = "wganchor"

// instanceComment is the exact comment string every rule this tool
// creates for instance is tagged with, as nft prints it (quoted). Always
// matched in full, never as a substring: "wganchor-instance-1" is a
// substring of "wganchor-instance-10", so a naive strings.Contains would
// make instance 1's presence check — and worse, its cleanup in
// disableInstanceFirewall — also match instance 10's rules.
func instanceComment(instance int) string {
	return fmt.Sprintf("wganchor-instance-%d", instance)
}

// quotedInstanceComment is instanceComment as it appears verbatim in
// `nft -a list chain` output: comment "wganchor-instance-<N>".
func quotedInstanceComment(instance int) string {
	return fmt.Sprintf("comment %q", instanceComment(instance))
}

// instanceSetName is the name of the tcp or udp allowed-port set for
// instance ("tcp" or "udp" — anything else is a programmer error, not
// validated here since callers already validate the port spec).
func instanceSetName(instance int, proto string) string {
	return fmt.Sprintf("wganchor%d_%s", instance, proto)
}

// firewallTableExists reports whether the shared `ip wganchor` table
// exists at all.
func firewallTableExists() bool {
	return commandSucceeds("nft", "list", "table", "ip", firewallTable)
}

// ensureFirewallTable idempotently creates the shared `ip wganchor`
// table and its single `input` chain (hooked once for the whole tool,
// policy accept so every other interface — LAN, Tailscale, Docker
// bridges, SSH — is completely unaffected). `nft add` is a no-op when
// the table/chain already exists with identical content, so this never
// touches any other table and is safe to call on every bring-up.
func ensureFirewallTable() error {
	if _, err := runCmd("nft", "add", "table", "ip", firewallTable); err != nil {
		return err
	}
	_, err := runCmd("nft", "add", "chain", "ip", firewallTable, "input",
		"{ type filter hook input priority filter; policy accept; }")
	return err
}

// ensureInstanceSets idempotently creates instance's tcp/udp allowed-port
// sets if absent, with `flags interval` so they can hold a range element
// like `{ 8000-8010 }` as well as an ordinary single-port element like
// `{ 8080 }` — confirmed empirically (plan-firewall-port-specs.md's
// step-0 spike) that an interval-flagged set accepts both shapes
// transparently, with a single port read back as a bare integer, not a
// length-1 range, so no config migration is needed for existing
// single-port entries. `nft add set` is a no-op if the set already
// exists with identical content. A set that already exists *without*
// this flag (created by a wganchor binary predating this change) is not
// touched here — see migrateStaleInstanceSets, which must run first.
func ensureInstanceSets(instance int) error {
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := runCmd("nft", "add", "set", "ip", firewallTable, instanceSetName(instance, proto),
			"{ type inet_service; flags interval; }"); err != nil {
			return err
		}
	}
	return nil
}

// setListingLacksIntervalFlag reports whether an `nft list set` listing
// predates the flags-interval schema change — extracted as a plain
// string predicate (mirroring isNftAbsentOutput) so setNeedsMigration's
// detection logic is directly unit-testable against a synthetic listing,
// with no `nft` invocation needed in tests.
func setListingLacksIntervalFlag(listing string) bool {
	return !strings.Contains(listing, "flags interval")
}

// setNeedsMigration reports whether instance's proto set exists but
// predates the flags-interval schema change. A brand-new or altogether
// absent set (`nft list set` failing with isNftAbsentOutput) is not
// stale — there's nothing to migrate, ensureInstanceSets will create it
// correctly from scratch.
func setNeedsMigration(instance int, proto string) (bool, error) {
	listing, err := runCmd("nft", "list", "set", "ip", firewallTable, instanceSetName(instance, proto))
	if err != nil {
		if isNftAbsentOutput(err.Error()) {
			return false, nil
		}
		return false, err
	}
	return setListingLacksIntervalFlag(listing), nil
}

// migrateStaleInstanceSets deletes any of instance's tcp/udp sets that
// predate the flags-interval schema change, so a subsequent
// ensureInstanceSets call recreates them correctly, and reports whether
// it actually migrated anything (migrated == false is a true no-op: no
// stale set existed — including the ordinary "firewall never enabled for
// this instance" case — so nothing was touched). Callers that already
// unconditionally call ensureInstanceSets/ensureInstanceBaseRules right
// after this (ensureFirewallScaffold) can ignore the return value; a
// caller that does NOT otherwise recreate the scaffold (FirewallDeny)
// must check it and recreate only when true — recreating unconditionally
// would turn a `deny` against a never-enabled or explicitly `disable`d
// instance into an unwanted scaffold-creation side effect, since
// ensureInstanceSets/ensureInstanceBaseRules would then build a fresh
// table/sets/rules from nothing.
//
// Only if at least one set actually needs migrating does this also
// delete all 4 of instance's base rules first — not just the rule(s)
// referencing the migrating set(s). `nft add rule` (used by
// ensureInstanceBaseRules) only ever appends at the chain tail, with no
// "insert before" by comment (see ensureInstanceBaseRules's own
// comment): deleting only the affected proto's rule and letting it be
// re-added later would land the re-added accept rule *after* the
// still-present terminating drop rule, making it permanently dead and
// every previously-allowed port on that proto unreachable. Reusing
// ruleHandlesForInstance (the same full-teardown lookup
// disableInstanceFirewall already uses) to delete all 4 avoids that.
// This briefly leaves the instance's interface completely unfiltered
// (chain policy is accept) until the caller's ensureInstanceBaseRules
// call re-adds all 4 rules moments later — the same non-atomic-command
// tradeoff disableInstanceFirewall's own teardown already carries, now
// also reachable from an ordinary allow/deny/enable/bring-up, not just
// an explicit disable.
func migrateStaleInstanceSets(instance int) (migrated bool, err error) {
	stale := make(map[string]bool, 2)
	anyStale := false
	for _, proto := range []string{"tcp", "udp"} {
		s, err := setNeedsMigration(instance, proto)
		if err != nil {
			return false, err
		}
		stale[proto] = s
		if s {
			anyStale = true
		}
	}
	if !anyStale {
		return false, nil
	}

	listing, err := runCmd("nft", "-a", "list", "chain", "ip", firewallTable, "input")
	if err != nil {
		if !isNftAbsentOutput(err.Error()) {
			return false, err
		}
		listing = ""
	}
	for _, handle := range ruleHandlesForInstance(listing, instance) {
		if err := runNftTolerant("delete", "rule", "ip", firewallTable, "input",
			"handle", strconv.Itoa(handle)); err != nil {
			return false, err
		}
	}

	for _, proto := range []string{"tcp", "udp"} {
		if !stale[proto] {
			continue
		}
		if err := runNftTolerant("delete", "set", "ip", firewallTable, instanceSetName(instance, proto)); err != nil {
			return false, err
		}
	}
	return true, nil
}

// existingInstanceBaseRuleKinds reports which of instance's 4 base rule
// kinds ("established", "tcp", "udp", "drop") are already present in
// chain *and bound to name*, by scanning listing (the output of `nft -a
// list chain ip wganchor input`) for lines carrying both instance's
// *exact* comment and name's exact `iifname "<name>"` clause. A rule
// line for a different instance (or an unrelated rule with no comment at
// all) never matches, since quotedInstanceComment requires the full
// quoted string, not a substring. The iifname check matters too: if an
// operator changes interface_name, a rule with the right comment but the
// *old* iifname must not count as "present" — otherwise the new
// interface goes unfiltered while the drop rule guards an interface that
// no longer exists (see staleRuleHandlesForInstance, which finds exactly
// those leftover rules so ensureInstanceBaseRules can remove them).
func existingInstanceBaseRuleKinds(listing string, instance int, name string) map[string]bool {
	comment := quotedInstanceComment(instance)
	iifname := fmt.Sprintf("iifname %q", name)
	found := make(map[string]bool, 4)
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, comment) || !strings.Contains(line, iifname) {
			continue
		}
		switch {
		case strings.Contains(line, "ct state established,related"):
			found["established"] = true
		case strings.Contains(line, "tcp dport"):
			found["tcp"] = true
		case strings.Contains(line, "udp dport"):
			found["udp"] = true
		case strings.Contains(line, "drop"):
			found["drop"] = true
		}
	}
	return found
}

// staleRuleHandlesForInstance returns the nft rule handles of every rule
// carrying instance's exact comment but bound to a *different* iifname
// than name — leftover from an interface_name config change. These must
// be deleted before the correct rules are (re-)added, since leaving them
// in place means the drop rule protects an interface that no longer
// exists while the actual current interface has no filter on it at all.
func staleRuleHandlesForInstance(listing string, instance int, name string) []int {
	comment := quotedInstanceComment(instance)
	iifname := fmt.Sprintf("iifname %q", name)
	var handles []int
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, comment) || strings.Contains(line, iifname) {
			continue
		}
		idx := strings.LastIndex(line, "# handle ")
		if idx == -1 {
			continue
		}
		if h, err := strconv.Atoi(strings.TrimSpace(line[idx+len("# handle "):])); err == nil {
			handles = append(handles, h)
		}
	}
	return handles
}

// ensureInstanceBaseRules idempotently ensures the 4 base rules for
// instance's interface name exist in the shared input chain: accept
// established/related traffic, accept from the tcp/udp allowed-port
// sets, and drop everything else on that interface. Unlike `nft add
// table`/`add set`, `nft add rule` is never itself idempotent — it
// always appends a new rule — so presence must be checked first via
// existingInstanceBaseRuleKinds and only the missing kinds added. Any
// stale rule left over from a prior interface_name are deleted first
// (staleRuleHandlesForInstance), so a renamed interface converges to
// fully filtered rather than silently gaining a phantom drop rule for an
// interface that no longer exists.
func ensureInstanceBaseRules(name string, instance int) error {
	listing, err := runCmd("nft", "-a", "list", "chain", "ip", firewallTable, "input")
	if err != nil {
		return err
	}
	for _, handle := range staleRuleHandlesForInstance(listing, instance, name) {
		if err := runNftTolerant("delete", "rule", "ip", firewallTable, "input",
			"handle", strconv.Itoa(handle)); err != nil {
			return err
		}
	}
	found := existingInstanceBaseRuleKinds(listing, instance, name)
	comment := instanceComment(instance)

	rules := []struct {
		kind string
		args []string
	}{
		{"established", []string{"iifname", name, "ct", "state", "established,related", "accept", "comment", comment}},
		{"tcp", []string{"iifname", name, "tcp", "dport", "@" + instanceSetName(instance, "tcp"), "accept", "comment", comment}},
		{"udp", []string{"iifname", name, "udp", "dport", "@" + instanceSetName(instance, "udp"), "accept", "comment", comment}},
		{"drop", []string{"iifname", name, "counter", "drop", "comment", comment}},
	}
	// Missing rules are appended at the tail, in "established, tcp, udp,
	// drop" order. That invariant — drop always last — holds as long as
	// this function is the only thing adding rules for an instance: a
	// partial failure (this loop stops after any error) only ever
	// truncates a suffix of that order, so a retry's re-added rules stay
	// correctly ordered. It would NOT hold if something external deleted
	// only a middle rule (e.g. just the tcp-accept) by handle — the
	// re-added accept would land after the existing drop and never
	// match. Not handled here; nft's rule chain has no "insert before"
	// by comment, only by handle or position.
	for _, r := range rules {
		if found[r.kind] {
			continue
		}
		args := append([]string{"add", "rule", "ip", firewallTable, "input"}, r.args...)
		if _, err := runCmd("nft", args...); err != nil {
			return err
		}
	}
	return nil
}

// isNftAbsentOutput reports whether combined `nft` output indicates
// "this element/rule/set/table doesn't exist" rather than a real
// failure — confirmed empirically: nft reports a missing table/set/rule
// as "No such file or directory", the same predicate style as
// isUnitNotInstalledOutput (lifecycle.go) for systemctl's equivalent
// "already in the state you wanted" case.
//
// A missing *element* in an interval-flagged set (flags interval, added
// by plan-firewall-port-specs.md) is reported differently — "element
// does not exist" — confirmed empirically and caught in implementation
// review: without this second match, `denyPortRange` against an
// already-absent element (the ordinary "deny a port that isn't allowed"
// no-op, or denying a sub-range that doesn't exactly match an allowed
// range, both explicitly documented as no-ops in docs/arch/firewall.md
// and README.md) would return this as a hard error instead. This also
// covers the exact same "element does not exist" wording nft uses for a
// non-matching sub-range delete against a real range element (e.g.
// deleting `{ 8005 }` from a set holding `8000-8010`), which is exactly
// the no-op the docs promise.
//
// Deliberately does NOT match "Device or resource busy" (nft's error
// when deleting a set a rule still references) — that's a real ordering
// bug, not a no-op.
func isNftAbsentOutput(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no such file or directory") ||
		strings.Contains(lower, "element does not exist")
}

// runNftTolerant runs an nft command, treating "target already absent"
// as success per isNftAbsentOutput, matching disableInstanceFirewall/
// denyPort's shared tolerance requirement.
func runNftTolerant(args ...string) error {
	_, err := runCmd("nft", args...)
	if err == nil {
		return nil
	}
	if isNftAbsentOutput(err.Error()) {
		return nil
	}
	return err
}

// portRangeElement builds the nft element literal for [start, end]: a
// single port (`{ <port> }`) when start == end, a range (`{ <start>-<end>
// }`) otherwise — both accepted transparently by an interval-flagged set
// (see ensureInstanceSets).
func portRangeElement(start, end int) string {
	if start == end {
		return fmt.Sprintf("{ %d }", start)
	}
	return fmt.Sprintf("{ %d-%d }", start, end)
}

// allowPortRange adds [start, end]/proto to instance's allowed-port set.
// `nft add element` is a no-op if the element is already present. Adding
// a range that overlaps an already-present element is rejected by `nft`
// itself with "interval overlaps with an existing one" (confirmed
// empirically) — surfaced as-is via runCmd's error formatting, not
// specially handled: overlap detection/merging is out of scope (see
// plan-firewall-port-specs.md's Non-goals).
func allowPortRange(instance, start, end int, proto string) error {
	_, err := runCmd("nft", "add", "element", "ip", firewallTable, instanceSetName(instance, proto),
		portRangeElement(start, end))
	return err
}

// denyPortRange removes [start, end]/proto from instance's allowed-port
// set, tolerating "already absent" as success (unlike `add`, `nft delete
// element` errors on an absent element). Exact-element-match only: a
// deny for a sub-range of a previously-allowed wider range is a no-op,
// not a partial split (see plan-firewall-port-specs.md's Non-goals).
func denyPortRange(instance, start, end int, proto string) error {
	return runNftTolerant("delete", "element", "ip", firewallTable, instanceSetName(instance, proto),
		portRangeElement(start, end))
}

// ruleHandlesForInstance returns the nft rule handles (from `nft -a
// list chain`'s trailing "# handle <N>") of every rule in the chain
// carrying instance's exact comment.
func ruleHandlesForInstance(listing string, instance int) []int {
	comment := quotedInstanceComment(instance)
	var handles []int
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, comment) {
			continue
		}
		idx := strings.LastIndex(line, "# handle ")
		if idx == -1 {
			continue
		}
		if h, err := strconv.Atoi(strings.TrimSpace(line[idx+len("# handle "):])); err == nil {
			handles = append(handles, h)
		}
	}
	return handles
}

// anyOtherInstanceRuleRemains reports whether the chain listing still
// carries any wganchor-instance-* comment other than excludeInstance's —
// a prefix scan is fine here (unlike the exact-match requirement
// elsewhere), since this only needs "is anything else still using this
// table", not "which exact instance".
func anyOtherInstanceRuleRemains(listing string, excludeInstance int) bool {
	exclude := instanceComment(excludeInstance)
	for _, line := range strings.Split(listing, "\n") {
		idx := strings.Index(line, "comment \"wganchor-instance-")
		if idx == -1 {
			continue
		}
		rest := line[idx+len("comment \""):]
		end := strings.Index(rest, "\"")
		if end == -1 {
			continue
		}
		if rest[:end] != exclude {
			return true
		}
	}
	return false
}

// disableInstanceFirewall removes exactly instance's firewall state:
// its 4 base rules (by exact comment match, deleted by handle) before
// its 2 sets — nft refuses to delete a set a rule still references, so
// this order is required, not just the end state — then drops the
// shared table entirely if no other instance's rules remain in it
// (mirrors lifecycle.go's removeTemplateIfUnused: only remove the shared
// thing once nothing else depends on it). Tolerates a table/chain/rules/
// sets that are already partially or fully absent as success, not an
// error — covering both a previous partial teardown and an instance
// whose firewall was never enabled to begin with (e.g. uninstall
// --purge on a server-role instance, or nft never installed at all).
func disableInstanceFirewall(instance int) error {
	if !firewallTableExists() {
		return nil
	}

	listing, err := runCmd("nft", "-a", "list", "chain", "ip", firewallTable, "input")
	if err != nil {
		if isNftAbsentOutput(err.Error()) {
			return nil
		}
		return err
	}

	for _, handle := range ruleHandlesForInstance(listing, instance) {
		if err := runNftTolerant("delete", "rule", "ip", firewallTable, "input",
			"handle", strconv.Itoa(handle)); err != nil {
			return err
		}
	}
	othersRemain := anyOtherInstanceRuleRemains(listing, instance)

	for _, proto := range []string{"tcp", "udp"} {
		if err := runNftTolerant("delete", "set", "ip", firewallTable, instanceSetName(instance, proto)); err != nil {
			return err
		}
	}

	if othersRemain {
		return nil
	}
	return runNftTolerant("delete", "table", "ip", firewallTable)
}

// ensureFirewallScaffold idempotently ensures the shared table and
// instance's sets/base rules all exist — the fixed part of instance's
// firewall that never depends on which ports are currently allowed.
// Shared by `firewall enable` and server/client's own bring-up (Step 3).
func ensureFirewallScaffold(name string, instance int) error {
	if err := ensureFirewallTable(); err != nil {
		return err
	}
	if _, err := migrateStaleInstanceSets(instance); err != nil {
		return err
	}
	if err := ensureInstanceSets(instance); err != nil {
		return err
	}
	return ensureInstanceBaseRules(name, instance)
}

// parseSetElements extracts the port-or-range tokens ("8080" or
// "8000-8010") from `nft list set`'s "elements = { ... }" line as raw
// strings — absent entirely for an empty set (an empty set's listing has
// no "elements" line at all, confirmed empirically). Returning strings
// rather than []int lets currentAllowedPorts append "/<proto>" uniformly
// to either shape, matching the exact "%d/%s" / "%d-%d/%s" format
// formatPortSpec produces.
func parseSetElements(listing string) []string {
	idx := strings.Index(listing, "elements = {")
	if idx == -1 {
		return nil
	}
	rest := listing[idx+len("elements = {"):]
	end := strings.Index(rest, "}")
	if end == -1 {
		return nil
	}
	var tokens []string
	for _, tok := range strings.Split(rest[:end], ",") {
		if tok = strings.TrimSpace(tok); tok != "" {
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// currentAllowedPorts reads instance's live tcp/udp sets and returns
// them as "<port>/<proto>" or "<start>-<end>/<proto>" strings, the same
// shape FirewallAllowedPorts persists. An absent set (firewall never
// enabled yet) is treated as empty, not an error, since
// applyFirewallAllowedPorts calls this before ensureFirewallScaffold is
// guaranteed to have run.
func currentAllowedPorts(instance int) ([]string, error) {
	var specs []string
	for _, proto := range []string{"tcp", "udp"} {
		listing, err := runCmd("nft", "list", "set", "ip", firewallTable, instanceSetName(instance, proto))
		if err != nil {
			if isNftAbsentOutput(err.Error()) {
				continue
			}
			return nil, err
		}
		for _, tok := range parseSetElements(listing) {
			specs = append(specs, fmt.Sprintf("%s/%s", tok, proto))
		}
	}
	return specs, nil
}

// applyFirewallAllowedPorts converges instance's live tcp/udp sets to
// exactly desired (each a "<port>/<proto>" string) — add missing, remove
// stale, the same diffRelayIPs-shaped diff-and-apply already used for
// relay_ips, just applied to ports instead of IPs. This is what makes an
// `allow`ed port survive a reboot: bring-up calls this on every
// invocation, converging the fresh, empty post-reboot sets back to the
// last-recorded intent.
func applyFirewallAllowedPorts(instance int, desired []string) error {
	current, err := currentAllowedPorts(instance)
	if err != nil {
		return err
	}
	toAdd, toRemove := diffRelayIPs(desired, current)
	for _, spec := range toRemove {
		start, end, proto, err := parsePortSpec(spec)
		if err != nil {
			// Unreachable in practice: every entry in current came from
			// currentAllowedPorts's own fmt.Sprintf("%s/%s", ...), which
			// always round-trips through parsePortSpec. Kept as a guard
			// rather than a panic in case that invariant ever changes.
			continue
		}
		if err := denyPortRange(instance, start, end, proto); err != nil {
			return err
		}
	}
	for _, spec := range toAdd {
		start, end, proto, err := parsePortSpec(spec)
		if err != nil {
			return fmt.Errorf("firewall_allowed_ports entry: %w", err)
		}
		if err := allowPortRange(instance, start, end, proto); err != nil {
			return err
		}
	}
	return nil
}

// parsePortSpec parses "<port>/<tcp|udp>" (e.g. "8080/tcp") or
// "<start>-<end>/<tcp|udp>" (e.g. "8000-8010/tcp"), rejecting anything
// else with an actionable error — matches validate.go's existing
// fail-fast posture for malformed input. A single port normalizes to
// start == end, so every downstream consumer (allowPortRange,
// currentAllowedPorts, ...) handles both shapes uniformly with no
// separate single-port code path. "both" is never a valid proto here —
// expandBothProto handles it at the CLI layer before a spec ever reaches
// this function.
func parsePortSpec(spec string) (start, end int, proto string, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, "", fmt.Errorf("invalid port spec %q: want <port>/<tcp|udp> or <start>-<end>/<tcp|udp>, e.g. 8080/tcp or 8000-8010/tcp", spec)
	}
	if parts[1] != "tcp" && parts[1] != "udp" {
		return 0, 0, "", fmt.Errorf("invalid port spec %q: protocol must be tcp or udp", spec)
	}
	proto = parts[1]

	if lo, hi, isRange := strings.Cut(parts[0], "-"); isRange {
		start, err = strconv.Atoi(lo)
		if err != nil {
			return 0, 0, "", fmt.Errorf("invalid port spec %q: range start must be an integer", spec)
		}
		end, err = strconv.Atoi(hi)
		if err != nil {
			return 0, 0, "", fmt.Errorf("invalid port spec %q: range end must be an integer", spec)
		}
	} else {
		start, err = strconv.Atoi(parts[0])
		if err != nil {
			return 0, 0, "", fmt.Errorf("invalid port spec %q: port must be an integer between 1 and 65535", spec)
		}
		end = start
	}
	if start < 1 || start > 65535 || end < 1 || end > 65535 {
		return 0, 0, "", fmt.Errorf("invalid port spec %q: ports must be between 1 and 65535", spec)
	}
	if start > end {
		return 0, 0, "", fmt.Errorf("invalid port spec %q: range start must be <= end", spec)
	}
	return start, end, proto, nil
}

// formatPortSpec is parsePortSpec's inverse: the canonical
// "<port>/<proto>" or "<start>-<end>/<proto>" string persisted to
// FirewallAllowedPorts and compared against in
// applyFirewallAllowedPorts's diffing. A single port's representation
// (start == end) is byte-for-byte unchanged from before ranges existed,
// so no config migration is needed for existing entries.
func formatPortSpec(start, end int, proto string) string {
	if start == end {
		return fmt.Sprintf("%d/%s", start, proto)
	}
	return fmt.Sprintf("%d-%d/%s", start, end, proto)
}

// expandBothProto returns spec unchanged, or — if spec ends in "/both" —
// the equivalent ["<base>/tcp", "<base>/udp"] pair. Pure, CLI-layer
// only: "both" is never a value parsePortSpec, FirewallAllowedPorts, or
// any nft set element ever needs to understand.
func expandBothProto(spec string) []string {
	base, ok := strings.CutSuffix(spec, "/both")
	if !ok {
		return []string{spec}
	}
	return []string{base + "/tcp", base + "/udp"}
}

// nftAvailable reports whether nft is on PATH — used by main.go's client
// bring-up so it can fail with errNftMissing's actionable message before
// touching any tunnel state, mirroring precheckFirewallCmd's own check.
func nftAvailable() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// errNftMissing is the single, actionable message for "nft isn't on
// PATH" — shared by precheckFirewallCmd (the `firewall` subcommands) and
// main.go's client bring-up path, so an operator sees the same guidance
// (use `firewall disable` to opt out durably) regardless of which code
// path first noticed nft was missing.
var errNftMissing = fmt.Errorf("nft not found on PATH; this host cannot run wganchor's firewall (use `wganchor firewall disable` to opt out durably, or pass --no-firewall for this run)")

// precheckFirewallCmd validates the shared preconditions for the four
// `firewall` subcommands and loads the instance's config — the config
// must already exist, since that's where the persisted intent this
// feature relies on lives (configPathForInstance, lifecycle.go): an
// `allow`/`enable` against a nonexistent config has nowhere to record
// its intent. requireNft additionally requires `nft` on PATH; every
// subcommand except `disable` needs it — `disable` must work even
// without nft so it remains the durable opt-out for an nft-less
// installed instance (docs/sprints/.../plan-firewall.md's "durable
// opt-out on a host without nft").
func precheckFirewallCmd(instance int, requireNft bool) (cfg *Config, path string, err error) {
	if os.Geteuid() != 0 {
		return nil, "", fmt.Errorf("must be run as root")
	}
	if requireNft {
		if _, lookErr := exec.LookPath("nft"); lookErr != nil {
			return nil, "", errNftMissing
		}
	}
	path = configPathForInstance(instance)
	cfg, err = loadConfig(path)
	if err != nil {
		return nil, "", fmt.Errorf("no config for instance %d at %s: %w", instance, path, err)
	}
	return cfg, path, nil
}

// firewallInterfaceName resolves cfg's interface name, falling back to
// the per-instance default the same way main.go's run() and watch.go's
// reconcileOnce already do. A thin wrapper around resolveRuntimeDefaults
// (config.go) — kept as a separate, name-only function since most
// firewall.go call sites have no use for the resolved listen port, but
// delegating avoids a second copy of the same fallback logic drifting
// out of sync (the exact risk this plan's validateRelayIP extraction was
// written to avoid elsewhere), caught in implementation review.
func firewallInterfaceName(cfg *Config, instance int) string {
	name, _ := resolveRuntimeDefaults(cfg, instance)
	return name
}

// FirewallEnable idempotently ensures instance's firewall scaffold
// exists and its live allowed-port sets match FirewallAllowedPorts
// exactly, then persists DisableFirewall = false. Re-applying the
// recorded ports here — not just waiting for the next server/client
// bring-up — is what makes a disable/enable round trip fully converge
// immediately: an operator re-enabling right after a disable should not
// see a firewall with the right scaffold but stale/empty port sets.
func FirewallEnable(instance int) error {
	cfg, path, err := precheckFirewallCmd(instance, true)
	if err != nil {
		return err
	}
	if err := ensureFirewallScaffold(firewallInterfaceName(cfg, instance), instance); err != nil {
		return err
	}
	if err := applyFirewallAllowedPorts(instance, cfg.FirewallAllowedPorts); err != nil {
		return err
	}
	if !cfg.DisableFirewall {
		return nil
	}
	cfg.DisableFirewall = false
	return persistConfig(cfg, path)
}

// addPortSpec appends spec to list if not already present, reporting
// whether it changed the list — the pure "allow" list-mutation logic,
// extracted out of FirewallAllow so it's directly unit-testable without
// invoking nft, touching config, or requiring root.
func addPortSpec(list []string, spec string) ([]string, bool) {
	for _, existing := range list {
		if existing == spec {
			return list, false
		}
	}
	return append(list, spec), true
}

// removePortSpec removes spec from list if present, reporting whether it
// changed the list — the pure "deny" list-mutation logic, extracted out
// of FirewallDeny for the same reason as addPortSpec.
func removePortSpec(list []string, spec string) ([]string, bool) {
	filtered := make([]string, 0, len(list))
	changed := false
	for _, existing := range list {
		if existing == spec {
			changed = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !changed {
		return list, false
	}
	return filtered, true
}

// FirewallAllow adds port/proto to instance's live allowed-port set and
// persists it to FirewallAllowedPorts so it survives a reboot. Also
// ensures the scaffold exists and clears DisableFirewall, matching
// docs/arch/firewall.md's statement that `allow` (not just `enable`) can
// turn firewalling back on for an instance that was `disable`d or never
// brought up — otherwise an `allow` right after a `disable`, or before
// the instance's first bring-up, would silently do nothing live.
func FirewallAllow(instance, start, end int, proto string) error {
	cfg, path, err := precheckFirewallCmd(instance, true)
	if err != nil {
		return err
	}
	if err := ensureFirewallScaffold(firewallInterfaceName(cfg, instance), instance); err != nil {
		return err
	}
	spec := formatPortSpec(start, end, proto)
	newList, listChanged := addPortSpec(cfg.FirewallAllowedPorts, spec)
	// Converge the whole recorded list (not just add this one port) for
	// the same reason FirewallEnable does: if the scaffold was just
	// rebuilt from scratch (a disable→allow round trip, or an
	// externally-torn-down table), the live sets are empty regardless of
	// what FirewallAllowedPorts already claims, so re-applying only the
	// new port would leave every previously-recorded port persisted in
	// config but dark until the next enable/bring-up.
	if err := applyFirewallAllowedPorts(instance, newList); err != nil {
		return err
	}
	if !listChanged && !cfg.DisableFirewall {
		return nil
	}
	cfg.FirewallAllowedPorts = newList
	cfg.DisableFirewall = false
	return persistConfig(cfg, path)
}

// FirewallDeny removes port/proto from instance's live allowed-port set
// and its persisted record. Runs migrateStaleInstanceSets first, not the
// full ensureFirewallScaffold FirewallAllow/FirewallEnable use — deny
// must stay a true no-op against an instance that was never enabled or
// was explicitly disabled. migrateStaleInstanceSets is itself a no-op
// when no set is stale (including the ordinary "never enabled" case,
// since an absent set is never "stale"), but a range deny against a set
// that predates the flags-interval schema does need migrating first:
// `nft delete element` against a non-interval set for a range spec fails
// outright ("You must add 'flags interval' to your set declaration"),
// which would make `deny` unable to ever remove such an entry — caught
// in implementation review. When migration actually happens here, it
// tears down the (already-existing, since a stale set only exists inside
// an already-created table) sets/base rules — ensureInstanceSets/
// ensureInstanceBaseRules restore exactly what was just torn down,
// completing the migration rather than leaving the instance
// unexpectedly unfiltered until some later call happens to do it. This
// is why the recreation is conditional on `migrated`, not unconditional
// like ensureFirewallScaffold's: unconditionally recreating would turn a
// `deny` against a never-enabled/disabled instance into an unwanted
// scaffold-creation side effect.
//
// migrateStaleInstanceSets's set deletion also empties out whatever was
// previously allowed on the migrating set(s) — confirmed live while
// verifying this fix: a deny that happens to trigger migration on a set
// with other, unrelated ports already allowed on it would otherwise
// silently drop them, which is a worse outcome than the bug being fixed.
// applyFirewallAllowedPorts(instance, cfg.FirewallAllowedPorts) restores
// them from the still-current persisted record (not yet touched at this
// point — the entry actually being denied is removed from it below,
// after the live nft deletion succeeds) before the deny itself proceeds.
func FirewallDeny(instance, start, end int, proto string) error {
	cfg, path, err := precheckFirewallCmd(instance, true)
	if err != nil {
		return err
	}
	migrated, err := migrateStaleInstanceSets(instance)
	if err != nil {
		return err
	}
	// Gated on !cfg.DisableFirewall (nit from implementation review): a
	// disabled instance's stale sets can survive FirewallDisable's own
	// teardown in one narrow case (nft was missing when disable ran, so
	// the live teardown was skipped entirely — see FirewallDisable). If
	// nft later reappears and `deny` happens to run against such an
	// instance, migration must still not resurrect a filtered scaffold
	// the operator explicitly disabled; leave the stale set(s) as-is.
	if migrated && !cfg.DisableFirewall {
		if err := ensureInstanceSets(instance); err != nil {
			return err
		}
		if err := ensureInstanceBaseRules(firewallInterfaceName(cfg, instance), instance); err != nil {
			return err
		}
		if err := applyFirewallAllowedPorts(instance, cfg.FirewallAllowedPorts); err != nil {
			return err
		}
	}
	if err := denyPortRange(instance, start, end, proto); err != nil {
		return err
	}
	spec := formatPortSpec(start, end, proto)
	newList, changed := removePortSpec(cfg.FirewallAllowedPorts, spec)
	if !changed {
		return nil
	}
	cfg.FirewallAllowedPorts = newList
	return persistConfig(cfg, path)
}

// FirewallDisable removes instance's live firewall state and persists
// DisableFirewall = true — the durable opt-out, deliberately tolerant of
// `nft` being completely absent from the host (skips the live teardown
// entirely in that case; disableInstanceFirewall's own "already gone"
// tolerance covers an absent table the same as an absent nft binary).
// Does NOT clear FirewallAllowedPorts: DisableFirewall alone makes the
// list inert, and clearing it would silently lose the operator's allow
// list across a disable/enable round trip — `deny` remains the only way
// to actually remove a port.
func FirewallDisable(instance int) error {
	cfg, path, err := precheckFirewallCmd(instance, false)
	if err != nil {
		return err
	}
	if _, nftErr := exec.LookPath("nft"); nftErr == nil {
		if err := disableInstanceFirewall(instance); err != nil {
			return err
		}
	}
	if cfg.DisableFirewall {
		return nil
	}
	cfg.DisableFirewall = true
	return persistConfig(cfg, path)
}
