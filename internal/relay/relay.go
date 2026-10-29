// Package relay implements `wganchor relay add|remove`: mutating an
// instance's relay_ips and live-applying the change, per
// docs/sprints/relay-and-firewall-ops/plan-relay-management.md.
package relay

import (
	"fmt"
	"os"

	"github.com/Rose-Vibe/wganchor/internal/config"
	"github.com/Rose-Vibe/wganchor/internal/routing"
	"github.com/Rose-Vibe/wganchor/internal/wireguard"
)

// addRelayIP appends ip to list if not already present, reporting whether
// it changed the list — the pure "add" list-mutation logic, mirroring
// internal/firewall's addPortSpec exactly so Add's core is directly
// unit-testable with no config, no root, no `ip`/`wg`.
func addRelayIP(list []string, ip string) ([]string, bool) {
	for _, existing := range list {
		if existing == ip {
			return list, false
		}
	}
	return append(list, ip), true
}

// removeRelayIP removes ip from list if present, reporting whether it
// changed the list — mirrors internal/firewall's removePortSpec.
func removeRelayIP(list []string, ip string) ([]string, bool) {
	filtered := make([]string, 0, len(list))
	changed := false
	for _, existing := range list {
		if existing == ip {
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

// applyRelayListChange persists cfg.RelayIPs = updated to path when
// changed, otherwise leaves the file untouched. Split out from
// Add/Remove so the persist step is unit-testable independent
// of precheckRelayCmd's root requirement and liveApplyRelay's ip/wg
// dependency.
func applyRelayListChange(cfg *config.Config, path string, updated []string, changed bool) error {
	if !changed {
		return nil
	}
	cfg.RelayIPs = updated
	return config.Persist(cfg, path)
}

// precheckRelayCmd validates the shared preconditions for `relay
// add`/`relay remove` and loads the instance's config — mirrors
// internal/firewall's precheckFirewallCmd, but never requires `nft`:
// relay's live-apply path only ever touches `ip`/`wg` state
// (ConfigureInterface, Reconcile*), not the firewall.
func precheckRelayCmd(instance int) (cfg *config.Config, path string, err error) {
	if os.Geteuid() != 0 {
		return nil, "", fmt.Errorf("must be run as root")
	}
	path = config.PathForInstance(instance)
	cfg, err = config.Load(path)
	if err != nil {
		return nil, "", fmt.Errorf("no config for instance %d at %s: %w", instance, path, err)
	}
	return cfg, path, nil
}

// liveApplyRelay converges live WireGuard/kernel state to cfg.RelayIPs,
// if the instance's interface already exists — resolving the interface
// name (and listen port, for the server role below) via
// config.ResolveRuntimeDefaults's exact fallback pattern *before*
// checking existence, since cfg.InterfaceName can legitimately be blank
// on the hand-edited-JSON path this command targets (see
// plan-relay-management.md's "Live-apply" section): resolving it after
// would make wireguard.InterfaceExists("") spuriously read "not up yet"
// for an instance whose interface is very much up under its real default
// name, silently leaving a stale AllowedIPs/route in place.
//
// If the interface doesn't exist yet, this only prints a deferred-
// application note (mirroring InstallInstance's enable/start-split
// "note:" precedent) — it never brings the interface up itself, matching
// pair run's identical boundary.
func liveApplyRelay(role string, cfg *config.Config, instance int) error {
	// Both the interface name AND the listen port must come from
	// config.ResolveRuntimeDefaults, not cfg directly — cfg.ListenPort is
	// only ever defaulted inside run() (cmd/wganchor), never by
	// config.Load itself, so a hand-edited config that omits listen_port
	// (a legal, documented config per wireguard.md) would otherwise reach
	// ConfigureInterface's server-role `wg set ... listen-port 0` and
	// silently rebind the server to a random ephemeral port — the exact
	// same hazard class the interface-name default guards against,
	// caught in implementation review.
	name, listenPort := config.ResolveRuntimeDefaults(cfg, instance)
	if !wireguard.InterfaceExists(name) {
		fmt.Printf("interface %s is not up; recorded in %s; run `wganchor %s --instance %d` to bring it up\n",
			name, config.PathForInstance(instance), role, instance)
		return nil
	}

	if role == "server" {
		// ValidateConfig is not re-run here (this command's whole premise
		// is a hand-edited config, so unlike a normal bring-up an
		// existing interface doesn't guarantee the config is still
		// valid): guard against feeding wg opaque, unhelpful failures for
		// the two fields it can't function without.
		if cfg.PeerPublicKey == "" || cfg.PrivateKey == "" {
			return fmt.Errorf("cannot live-apply: peer_public_key or private_key is blank in the config; run `wganchor server --instance %d` to see the full validation error", instance)
		}
		// ReconcileServerRoutes only ever touches kernel routes — it never
		// touches the WireGuard peer's AllowedIPs, which on the server
		// role is derived directly from RelayIPs (AllowedIPsForRole,
		// internal/wireguard). WireGuard enforces AllowedIPs as its own
		// cryptokey-routing filter independent of the kernel routing
		// table, so re-running ConfigureInterface here is what actually
		// makes a newly-added relay IP forwardable — without it, the
		// kernel route alone would exist while WireGuard silently refused
		// to forward traffic to it. Applied against a shallow copy with
		// the resolved listen port, never persisted back to cfg/disk —
		// matching run()'s own "never persist a defaulted runtime value"
		// behavior.
		applied := *cfg
		applied.ListenPort = listenPort
		if err := wireguard.ConfigureInterface(&applied, role, name); err != nil {
			return err
		}
		_, err := routing.ReconcileServerRoutes(name, cfg.RelayIPs)
		return err
	}

	// Client: no ConfigureInterface re-call needed. The client's
	// AllowedIPs is always 0.0.0.0/0 regardless of RelayIPs
	// (AllowedIPsForRole, internal/wireguard), so nothing there depends
	// on this list. Also deliberately does NOT re-assert the firewall
	// scaffold before binding the new relay IP (unlike cmd/wganchor's
	// run(), which ensures the scaffold before ReconcileClientRouting
	// specifically so a firewall failure can never leave a public IP
	// briefly unfiltered): the existing base rules are already scoped by
	// iifname, not by which IPs are currently bound to it, so a
	// newly-added address is covered by the same already-live rules with
	// no gap. Re-asserting here would also silently re-enable a firewall
	// an operator deliberately brought the instance up with --no-firewall
	// to skip — a worse surprise than the (already covered) no-gap case.
	// Recorded as a considered decision (implementation review), not an
	// omission.
	_, err := routing.ReconcileClientRouting(name, cfg.RelayIPs, instance)
	return err
}

// liveApplyErrorGuidance wraps a live-apply failure with the same
// "config already updated, here's how to retry" guidance for both
// Add and Remove — the persisted change is never rolled back
// on a live-apply failure (recorded intent is preserved regardless), so
// the error must say so rather than reading like the whole command
// failed.
func liveApplyErrorGuidance(err error, sub, role string, instance int, ip string) error {
	return fmt.Errorf("%w (relay_ips was already updated in config; re-run `wganchor relay %s %s --instance %d --ip %s` "+
		"(idempotent) or `wganchor %s --instance %d` to retry)", err, sub, role, instance, ip, role, instance)
}

// Add implements `wganchor relay add <server|client> --instance N
// --ip <ipv4>`: idempotently adds ip to the instance's relay_ips and, if
// its interface already exists, immediately live-applies the change — so
// the common case needs no separate restart. See
// docs/sprints/relay-and-firewall-ops/plan-relay-management.md.
func Add(role string, instance int, ip string) error {
	if err := config.ValidateRelayIP(ip); err != nil {
		return fmt.Errorf("--ip: %w", err)
	}
	cfg, path, err := precheckRelayCmd(instance)
	if err != nil {
		return err
	}
	updated, changed := addRelayIP(cfg.RelayIPs, ip)
	if err := applyRelayListChange(cfg, path, updated, changed); err != nil {
		return err
	}
	if err := liveApplyRelay(role, cfg, instance); err != nil {
		return liveApplyErrorGuidance(err, "add", role, instance, ip)
	}
	return nil
}

// Remove implements `wganchor relay remove <server|client>
// --instance N --ip <ipv4>`. --ip is validated through
// config.ValidateRelayIP too, for the same "reject garbage input with an
// actionable error" symmetry Deny already has with Allow
// — not because a malformed IP would otherwise do anything unsafe
// (removeRelayIP would just no-op, since it wouldn't match any existing
// entry), but so an operator's typo on remove fails the same clear way
// it would on add.
//
// Removing relay_ips down to an empty list is allowed (not artificially
// restricted here): ValidateConfig already refuses any bring-up against
// an empty relay_ips list, which is the right place to enforce that.
func Remove(role string, instance int, ip string) error {
	if err := config.ValidateRelayIP(ip); err != nil {
		return fmt.Errorf("--ip: %w", err)
	}
	cfg, path, err := precheckRelayCmd(instance)
	if err != nil {
		return err
	}
	updated, changed := removeRelayIP(cfg.RelayIPs, ip)
	if err := applyRelayListChange(cfg, path, updated, changed); err != nil {
		return err
	}
	if changed && len(updated) == 0 {
		fmt.Printf("relay_ips is now empty; `wganchor %s --instance %d` will refuse to start until at least one IP is configured\n",
			role, instance)
	}
	if err := liveApplyRelay(role, cfg, instance); err != nil {
		return liveApplyErrorGuidance(err, "remove", role, instance, ip)
	}
	return nil
}
