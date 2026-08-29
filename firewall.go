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
// sets if absent. `nft add set` is a no-op if the set already exists.
func ensureInstanceSets(instance int) error {
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := runCmd("nft", "add", "set", "ip", firewallTable, instanceSetName(instance, proto),
			"{ type inet_service; }"); err != nil {
			return err
		}
	}
	return nil
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
// failure — confirmed empirically: nft reports a missing target as "No
// such file or directory", the same predicate style as
// isUnitNotInstalledOutput (lifecycle.go) for systemctl's equivalent
// "already in the state you wanted" case. Deliberately does NOT match
// "Device or resource busy" (nft's error when deleting a set a rule
// still references) — that's a real ordering bug, not a no-op.
func isNftAbsentOutput(output string) bool {
	return strings.Contains(strings.ToLower(output), "no such file or directory")
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

// allowPort adds port/proto to instance's allowed-port set. `nft add
// element` is a no-op if the element is already present.
func allowPort(instance int, port int, proto string) error {
	_, err := runCmd("nft", "add", "element", "ip", firewallTable, instanceSetName(instance, proto),
		fmt.Sprintf("{ %d }", port))
	return err
}

// denyPort removes port/proto from instance's allowed-port set,
// tolerating "already absent" as success (unlike `add`, `nft delete
// element` errors on an absent element).
func denyPort(instance int, port int, proto string) error {
	return runNftTolerant("delete", "element", "ip", firewallTable, instanceSetName(instance, proto),
		fmt.Sprintf("{ %d }", port))
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
	if err := ensureInstanceSets(instance); err != nil {
		return err
	}
	return ensureInstanceBaseRules(name, instance)
}

// parseSetElements extracts the port numbers from `nft list set`'s
// "elements = { ... }" line — absent entirely for an empty set (an
// empty set's listing has no "elements" line at all, confirmed
// empirically).
func parseSetElements(listing string) []int {
	idx := strings.Index(listing, "elements = {")
	if idx == -1 {
		return nil
	}
	rest := listing[idx+len("elements = {"):]
	end := strings.Index(rest, "}")
	if end == -1 {
		return nil
	}
	var ports []int
	for _, tok := range strings.Split(rest[:end], ",") {
		if p, err := strconv.Atoi(strings.TrimSpace(tok)); err == nil {
			ports = append(ports, p)
		}
	}
	return ports
}

// currentAllowedPorts reads instance's live tcp/udp sets and returns
// them as "<port>/<proto>" strings, the same shape FirewallAllowedPorts
// persists. An absent set (firewall never enabled yet) is treated as
// empty, not an error, since applyFirewallAllowedPorts calls this before
// ensureFirewallScaffold is guaranteed to have run.
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
		for _, port := range parseSetElements(listing) {
			specs = append(specs, fmt.Sprintf("%d/%s", port, proto))
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
		port, proto, err := parsePortSpec(spec)
		if err != nil {
			// Unreachable in practice: every entry in current came from
			// currentAllowedPorts's own fmt.Sprintf("%d/%s", ...), which
			// always round-trips through parsePortSpec. Kept as a guard
			// rather than a panic in case that invariant ever changes.
			continue
		}
		if err := denyPort(instance, port, proto); err != nil {
			return err
		}
	}
	for _, spec := range toAdd {
		port, proto, err := parsePortSpec(spec)
		if err != nil {
			return fmt.Errorf("firewall_allowed_ports entry: %w", err)
		}
		if err := allowPort(instance, port, proto); err != nil {
			return err
		}
	}
	return nil
}

// parsePortSpec parses a "<port>/<tcp|udp>" spec (e.g. "8080/tcp"),
// rejecting anything else with an actionable error — matches
// validate.go's existing fail-fast posture for malformed input.
func parsePortSpec(spec string) (port int, proto string, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, "", fmt.Errorf("invalid port spec %q: want <port>/<tcp|udp>, e.g. 8080/tcp", spec)
	}
	port, convErr := strconv.Atoi(parts[0])
	if convErr != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("invalid port spec %q: port must be an integer between 1 and 65535", spec)
	}
	if parts[1] != "tcp" && parts[1] != "udp" {
		return 0, "", fmt.Errorf("invalid port spec %q: protocol must be tcp or udp", spec)
	}
	return port, parts[1], nil
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
// reconcileOnce already do.
func firewallInterfaceName(cfg *Config, instance int) string {
	if cfg.InterfaceName != "" {
		return cfg.InterfaceName
	}
	return defaultInterfaceName(instance)
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
func FirewallAllow(instance, port int, proto string) error {
	cfg, path, err := precheckFirewallCmd(instance, true)
	if err != nil {
		return err
	}
	if err := ensureFirewallScaffold(firewallInterfaceName(cfg, instance), instance); err != nil {
		return err
	}
	spec := fmt.Sprintf("%d/%s", port, proto)
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
// and its persisted record.
func FirewallDeny(instance, port int, proto string) error {
	cfg, path, err := precheckFirewallCmd(instance, true)
	if err != nil {
		return err
	}
	if err := denyPort(instance, port, proto); err != nil {
		return err
	}
	spec := fmt.Sprintf("%d/%s", port, proto)
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
