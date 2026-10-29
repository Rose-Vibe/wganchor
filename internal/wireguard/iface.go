package wireguard

import (
	"fmt"
	"strings"

	"github.com/Rose-Vibe/wganchor/internal/config"
	"github.com/Rose-Vibe/wganchor/internal/sysexec"
)

// AllowedIPsForRole computes the WireGuard AllowedIPs list for this side's
// peer entry, per plan-tunnel-runtime.md: the server (VPS) side is scoped
// to exactly its relay IPs, the client (home) side must accept traffic to
// any destination — see docs/arch/overview.md's cryptokey-routing finding
// for why a narrow AllowedIPs breaks the outbound path on the client.
func AllowedIPsForRole(cfg *config.Config, role string) []string {
	if role == "client" {
		return []string{"0.0.0.0/0"}
	}
	allowed := make([]string, len(cfg.RelayIPs))
	for i, ip := range cfg.RelayIPs {
		allowed[i] = ip + "/32"
	}
	return allowed
}

// InterfaceExists reports whether an interface named name exists at all
// (of any type), via exit code rather than string-matching output.
func InterfaceExists(name string) bool {
	return sysexec.CommandSucceeds("ip", "link", "show", name)
}

// isWireGuardInterface reports whether an existing interface named name is
// actually a WireGuard device. `interface_name` is operator-overridable,
// so a name collision with an unrelated interface (a bridge, a veth, a
// different VPN's tunnel) is possible and must fail with an actionable
// error rather than a confusing downstream `wg set` failure.
func isWireGuardInterface(name string) bool {
	return sysexec.CommandSucceeds("wg", "show", name)
}

// EnsureInterface creates the WireGuard interface if it doesn't already
// exist. Idempotent: re-running against an already-correct interface is a
// no-op. Fails if name already exists but isn't a WireGuard device.
// created reports whether this call actually created the interface (vs.
// finding it already present) — used by the firewall feature to gate its
// one-time default-enable notice on genuine first-time creation,
// including after a reboot recreates the interface from scratch.
func EnsureInterface(name string) (created bool, err error) {
	if InterfaceExists(name) {
		if !isWireGuardInterface(name) {
			return false, fmt.Errorf("interface %s already exists and is not a WireGuard device", name)
		}
		return false, nil
	}
	if _, err := sysexec.RunCmd("ip", "link", "add", name, "type", "wireguard"); err != nil {
		return false, err
	}
	return true, nil
}

// ConfigureInterface sets the private key (server also sets listen-port)
// and the peer, then brings the interface up. The private key is piped to
// `wg set ... private-key /dev/stdin` over stdin rather than a file path —
// it never touches argv or disk at all. (A 0600 temp file was tried first
// and rejected: Ubuntu ships an AppArmor profile confining /usr/bin/wg to
// only open files under /etc/wireguard/, which a temp file elsewhere fails
// against with "fopen: Permission denied" — confirmed empirically against
// the real VPS. /dev/stdin sidesteps that confinement entirely rather than
// working around it by writing into /etc/wireguard/, which
// docs/arch/wireguard.md deliberately never does.)
func ConfigureInterface(cfg *config.Config, role, name string) error {
	setArgs := []string{"set", name, "private-key", "/dev/stdin"}
	if role == "server" {
		setArgs = append(setArgs, "listen-port", fmt.Sprintf("%d", cfg.ListenPort))
	}
	if _, err := sysexec.RunCmdStdin(cfg.PrivateKey, "wg", setArgs...); err != nil {
		return err
	}

	peerArgs := []string{
		"set", name, "peer", cfg.PeerPublicKey,
		"allowed-ips", strings.Join(AllowedIPsForRole(cfg, role), ","),
	}
	if role == "client" {
		peerArgs = append(peerArgs, "endpoint", cfg.PeerEndpoint)
		keepalive := cfg.PersistentKeepalive
		if keepalive == 0 {
			keepalive = 25
		}
		peerArgs = append(peerArgs, "persistent-keepalive", fmt.Sprintf("%d", keepalive))
	}
	if _, err := sysexec.RunCmd("wg", peerArgs...); err != nil {
		return err
	}

	_, err := sysexec.RunCmd("ip", "link", "set", name, "up")
	return err
}
