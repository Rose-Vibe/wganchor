package main

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// tableForInstance and priorityForInstance derive the client-side policy
// routing table ID and ip-rule priority deterministically from the
// instance number, reusing the already-collision-checked listen-port
// formula (docs/arch/wireguard.md's "Client-side policy routing" section)
// instead of inventing a second collision-prone constant. Instance 0
// reproduces the exact values validated by hand in the bootstrap PoC
// (table 60217, priority 20217).
func tableForInstance(instance int) int {
	return defaultListenPort(instance)
}

func priorityForInstance(instance int) int {
	return defaultListenPort(instance) - 40000
}

// diffRelayIPs compares the desired relay IP list against what's
// currently live and reports which need to be added and which are stale
// and need removing. Pure and deterministic (sorted output) for testing.
func diffRelayIPs(desired, current []string) (toAdd, toRemove []string) {
	desiredSet := make(map[string]bool, len(desired))
	for _, ip := range desired {
		desiredSet[ip] = true
	}
	currentSet := make(map[string]bool, len(current))
	for _, ip := range current {
		currentSet[ip] = true
	}
	for _, ip := range desired {
		if !currentSet[ip] {
			toAdd = append(toAdd, ip)
		}
	}
	for _, ip := range current {
		if !desiredSet[ip] {
			toRemove = append(toRemove, ip)
		}
	}
	sort.Strings(toAdd)
	sort.Strings(toRemove)
	return toAdd, toRemove
}

// parseRouteShowHostRoutes extracts /32 destination IPs from `ip route
// show dev <name>` output — the host routes ReconcileServerRoutes manages.
func parseRouteShowHostRoutes(output string) []string {
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if dest, ok := strings.CutSuffix(fields[0], "/32"); ok {
			ips = append(ips, dest)
		}
	}
	return ips
}

// parseAddrShowHostIPs extracts /32 addresses from `ip -4 addr show dev
// <name>` output — the addresses ReconcileClientRouting manages.
func parseAddrShowHostIPs(output string) []string {
	var ips []string
	fields := strings.Fields(output)
	for i, f := range fields {
		if f != "inet" || i+1 >= len(fields) {
			continue
		}
		if addr, ok := strings.CutSuffix(fields[i+1], "/32"); ok {
			ips = append(ips, addr)
		}
	}
	return ips
}

// ipRuleSourceToken reports whether tok is a plausible `ip rule` source
// selector — a bare IP (what this tool creates) or an IP/prefix (what an
// older or hand-edited rule might contain) — returning it unchanged so the
// caller can still delete it by its exact literal text. A wildcard
// selector ("all") or anything else that isn't IP-shaped returns "".
func ipRuleSourceToken(tok string) string {
	if net.ParseIP(tok) != nil {
		return tok
	}
	if _, _, err := net.ParseCIDR(tok); err == nil {
		return tok
	}
	return ""
}

// parseIPRuleShowForTable extracts the source selectors of `ip rule show`
// entries that route to table. Matches fields rather than a substring, so
// an unrelated rule that happens to contain the same text doesn't count.
// A wildcard rule (`from all ...`, e.g. an unrelated fwmark-based VPN
// app's rule) is deliberately excluded even if it targets the same
// numeric table — this tool only ever creates `from <ip>` rules, and
// treating "all" as a stale relay IP would issue `ip rule del from all
// table <N>` against a rule it never created.
func parseIPRuleShowForTable(output string, table int) []string {
	tableStr := strconv.Itoa(table)
	var ips []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		var ip string
		matchesTable := false
		for i, f := range fields {
			if f == "from" && i+1 < len(fields) {
				ip = ipRuleSourceToken(fields[i+1])
			}
			if (f == "lookup" || f == "table") && i+1 < len(fields) && fields[i+1] == tableStr {
				matchesTable = true
			}
		}
		if ip != "" && matchesTable {
			ips = append(ips, ip)
		}
	}
	return ips
}

// ReconcileResult reports what a Reconcile* call actually changed, so a
// caller (e.g. wganchor watch) can log only on real repairs instead of
// every idempotent no-op run.
type ReconcileResult struct {
	AddrsAdded, AddrsRemoved   []string
	RoutesAdded, RoutesRemoved []string
	RulesAdded, RulesRemoved   []string
}

// Changed reports whether this result reflects any actual live-state
// change.
func (r ReconcileResult) Changed() bool {
	return len(r.AddrsAdded) > 0 || len(r.AddrsRemoved) > 0 ||
		len(r.RoutesAdded) > 0 || len(r.RoutesRemoved) > 0 ||
		len(r.RulesAdded) > 0 || len(r.RulesRemoved) > 0
}

// buildReconcileResult assembles a ReconcileResult from the add/remove
// sets already computed by diffRelayIPs (and, for the client's table
// default route, hasDefaultRoute) — kept as a pure function, independent
// of runCmd, so it's directly unit-testable.
func buildReconcileResult(addrAdd, addrRemove, routeAdd, routeRemove, ruleAdd, ruleRemove []string) ReconcileResult {
	return ReconcileResult{
		AddrsAdded:    addrAdd,
		AddrsRemoved:  addrRemove,
		RoutesAdded:   routeAdd,
		RoutesRemoved: routeRemove,
		RulesAdded:    ruleAdd,
		RulesRemoved:  ruleRemove,
	}
}

// isFibTableMissingOutput reports whether `ip route show table <N>`
// output/error indicates the table has never had a route added to it —
// confirmed empirically ("Error: ipv4: FIB table does not exist.",
// exit 2) — rather than a real failure. Only ever true for a table
// number that has genuinely never been used; runCmd's own error
// formatting includes stderr, so err.Error() is enough to check.
func isFibTableMissingOutput(output string) bool {
	return strings.Contains(strings.ToLower(output), "fib table does not exist")
}

// hasDefaultRoute reports whether `ip route show table <N>` output
// already contains a default route out dev name, so
// ReconcileClientRouting can report a repair instead of silently
// absorbing it when the table's default route (not just the ip rule
// pointing at it) was externally dropped.
func hasDefaultRoute(output string, name string) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i, f := range fields {
			if f == "dev" && i+1 < len(fields) && fields[i+1] == name {
				return true
			}
		}
	}
	return false
}

// ReconcileServerRoutes ensures exactly relayIPs have a /32 host route to
// name, removing any stale route for a relay IP that's no longer
// configured. Only ever touches routes scoped to dev name, never a
// blind sweep of the routing table.
func ReconcileServerRoutes(name string, relayIPs []string) (ReconcileResult, error) {
	out, err := runCmd("ip", "route", "show", "dev", name)
	if err != nil {
		return ReconcileResult{}, err
	}
	current := parseRouteShowHostRoutes(out)
	toAdd, toRemove := diffRelayIPs(relayIPs, current)

	for _, ip := range toRemove {
		if _, err := runCmd("ip", "route", "del", ip+"/32", "dev", name); err != nil {
			return ReconcileResult{}, err
		}
	}
	for _, ip := range relayIPs {
		if _, err := runCmd("ip", "route", "replace", ip+"/32", "dev", name); err != nil {
			return ReconcileResult{}, err
		}
	}
	return buildReconcileResult(nil, nil, toAdd, toRemove, nil, nil), nil
}

// ReconcileClientRouting ensures each relay IP is locally bindable
// (address) and its outbound traffic is policy-routed through name,
// removing stale addresses/rules for any relay IP no longer configured.
// Never adds a kernel default route for name — see plan-tunnel-runtime.md
// on why a wide AllowedIPs must not become a default-route override.
func ReconcileClientRouting(name string, relayIPs []string, instance int) (ReconcileResult, error) {
	table := tableForInstance(instance)
	priority := priorityForInstance(instance)
	tableStr := strconv.Itoa(table)

	addrOut, err := runCmd("ip", "-4", "addr", "show", "dev", name)
	if err != nil {
		return ReconcileResult{}, err
	}
	addrAdd, addrRemove := diffRelayIPs(relayIPs, parseAddrShowHostIPs(addrOut))
	for _, ip := range addrRemove {
		if _, err := runCmd("ip", "addr", "del", ip+"/32", "dev", name); err != nil {
			return ReconcileResult{}, err
		}
	}
	for _, ip := range relayIPs {
		if _, err := runCmd("ip", "addr", "replace", ip+"/32", "dev", name); err != nil {
			return ReconcileResult{}, err
		}
	}

	ruleOut, err := runCmd("ip", "rule", "show")
	if err != nil {
		return ReconcileResult{}, err
	}
	currentRuleIPs := parseIPRuleShowForTable(ruleOut, table)
	ruleAdd, ruleRemove := diffRelayIPs(relayIPs, currentRuleIPs)
	for _, ip := range ruleRemove {
		if _, err := runCmd("ip", "rule", "del", "from", ip, "table", tableStr); err != nil {
			return ReconcileResult{}, err
		}
	}
	for _, ip := range ruleAdd {
		if _, err := runCmd("ip", "rule", "add", "from", ip, "table", tableStr,
			"priority", strconv.Itoa(priority)); err != nil {
			return ReconcileResult{}, err
		}
	}

	// A policy routing table with no route ever added to it yet doesn't
	// exist as far as the kernel's FIB is concerned — confirmed
	// empirically, `ip route show table <N>` exits 2 with "FIB table
	// does not exist" for a genuinely brand-new instance's first-ever
	// bring-up (table 60217 only "exists" once something has been added
	// to it, which the `replace` below is about to do for the first
	// time). That's "no default route present", not a real failure.
	routeTableOut, err := runCmd("ip", "route", "show", "table", tableStr)
	if err != nil && !isFibTableMissingOutput(err.Error()) {
		return ReconcileResult{}, err
	}
	var routeAdd []string
	if !hasDefaultRoute(routeTableOut, name) {
		routeAdd = []string{"default"}
	}
	if _, err := runCmd("ip", "route", "replace", "default", "dev", name, "table", tableStr); err != nil {
		return ReconcileResult{}, err
	}

	return buildReconcileResult(addrAdd, addrRemove, routeAdd, nil, ruleAdd, ruleRemove), nil
}

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// CheckIPForward reports whether IPv4 forwarding is enabled, per
// plan-tunnel-runtime.md's "confirm-only" warning on the server side —
// wganchor never sets this itself, that's plan-environment.md's job.
func CheckIPForward() (bool, error) {
	return ipForwardEnabled(ipForwardPath)
}

// ipForwardEnabled reads path directly (rather than shelling out to `cat`)
// so it's a plain, unit-testable function against a fixture file, per
// plan-tunnel-runtime.md's exit criteria ("unit-tested against the check
// function directly, not by mutating the real sysctl").
func ipForwardEnabled(path string) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is the fixed ipForwardPath constant in production, or a test fixture path in tests — never external input
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

const ipForwardWarning = "warning: net.ipv4.ip_forward is not 1 — inbound relay traffic will not be forwarded"
