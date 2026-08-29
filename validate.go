package main

import (
	"fmt"
	"net"
)

// ValidateConfig runs the pre-flight checks from
// docs/sprints/wireguard-automation/plan-tunnel-runtime.md before any
// system state is touched. Every failure is meant to be actionable: a
// misconfiguration should fail fast with a clear message, not silently
// no-op or surface later as an opaque `ip`/`wg` error.
func ValidateConfig(cfg *Config, role string) error {
	if cfg.PeerPublicKey == "" {
		return fmt.Errorf("peer_public_key is empty; nothing to peer with")
	}
	if role == "client" && cfg.PeerEndpoint == "" {
		return fmt.Errorf("peer_endpoint is empty; a client can never dial out without one")
	}
	if len(cfg.RelayIPs) == 0 {
		return fmt.Errorf("relay_ips is empty; nothing to relay")
	}
	seen := make(map[string]bool, len(cfg.RelayIPs))
	for i, raw := range cfg.RelayIPs {
		if err := validateRelayIP(raw); err != nil {
			return fmt.Errorf("relay_ips[%d] %w", i, err)
		}
		if seen[raw] {
			return fmt.Errorf("relay_ips[%d] is a duplicate of an earlier entry: %q", i, raw)
		}
		seen[raw] = true
	}
	return nil
}

// validateRelayIP validates a single relay_ips entry: IPv4 only, since
// EnsureInterface/ConfigureInterface and the routing reconciliation logic
// all assume /32 IPv4 addresses (ip -4 addr show, ip route show without
// -6) — an IPv6 entry would parse here and then fail confusingly three
// layers down. Extracted out of ValidateConfig's loop so `wganchor relay
// add`/`remove` (relay.go) can run the exact same check against a single
// --ip flag value, rather than a second copy that could drift.
func validateRelayIP(raw string) error {
	ip := net.ParseIP(raw)
	if ip == nil {
		return fmt.Errorf("is not a valid IP: %q", raw)
	}
	if ip.To4() == nil {
		return fmt.Errorf("is not an IPv4 address (IPv6 is not supported): %q", raw)
	}
	return nil
}
