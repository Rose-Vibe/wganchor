// Package config implements loading, validating, and persisting a
// wganchor instance's on-disk JSON config, per docs/arch/wireguard.md and
// docs/arch/config-and-lifecycle.md.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Dir is the system-daemon config directory, per
// docs/arch/config-and-lifecycle.md — the single source of truth for
// this path, shared with internal/lifecycle (which also creates and
// tears it down).
const Dir = "/etc/wganchor"

// Config is the on-disk schema for a single wganchor instance, per
// docs/arch/wireguard.md and docs/arch/config-and-lifecycle.md.
type Config struct {
	PrivateKey          string   `json:"private_key"`
	PeerPublicKey       string   `json:"peer_public_key"`
	PeerEndpoint        string   `json:"peer_endpoint,omitempty"`
	ListenPort          int      `json:"listen_port"`
	InterfaceName       string   `json:"interface_name"`
	RelayIPs            []string `json:"relay_ips"`
	PersistentKeepalive int      `json:"persistent_keepalive,omitempty"`

	// DisableFirewall and FirewallAllowedPorts record the operator's
	// last `wganchor firewall` intent so it survives a reboot (the
	// interface, and its just-created nftables scaffold, are destroyed
	// and recreated every reboot) — see docs/arch/firewall.md. Bring-up
	// re-applies this recorded state on every invocation, not just
	// first creation; nothing else ever re-diffs it on a timer.
	DisableFirewall      bool     `json:"disable_firewall,omitempty"`
	FirewallAllowedPorts []string `json:"firewall_allowed_ports,omitempty"` // e.g. "8080/tcp"
}

// Redacted returns a copy of cfg with PrivateKey masked, safe to print.
func (c Config) Redacted() Config {
	if c.PrivateKey != "" {
		c.PrivateKey = "(redacted)"
	}
	return c
}

var errNoConfigFound = errors.New("no config file found")

// DefaultInterfaceName and DefaultListenPort implement the uniform
// per-instance formula from docs/arch/wireguard.md: wganchor<N> /
// 60217+N, with N=0 identical to the unnumbered case.
func DefaultInterfaceName(instance int) string {
	return fmt.Sprintf("wganchor%d", instance)
}

// DefaultListenPort is DefaultInterfaceName's listen-port counterpart.
func DefaultListenPort(instance int) int {
	return 60217 + instance
}

// ResolveRuntimeDefaults returns cfg's interface name and listen port,
// falling back to the per-instance defaults (DefaultInterfaceName/
// DefaultListenPort) for whichever is left blank/zero in the config —
// the same fallback run() applies before ever touching live state. A
// config that omits either field means "use the default," not "the
// field doesn't matter yet." Shared by run() and internal/relay's
// liveApplyRelay so a hand-edited config missing listen_port can't reach
// ConfigureInterface with a zero port on the relay live-apply path —
// that would silently rebind WireGuard to a random ephemeral port
// (`wg set ... listen-port 0`) instead of the documented default, the
// same hazard class the interface-name default already guards against.
// liveApplyRelay never persists the resolved values back to cfg/disk;
// run() does (it assigns them onto cfg, which a subsequent first-run
// EnsureKeys then writes out) — that's pre-existing behavior from
// before this extraction, unchanged here.
func ResolveRuntimeDefaults(cfg *Config, instance int) (name string, listenPort int) {
	name = cfg.InterfaceName
	if name == "" {
		name = DefaultInterfaceName(instance)
	}
	listenPort = cfg.ListenPort
	if listenPort == 0 {
		listenPort = DefaultListenPort(instance)
	}
	return name, listenPort
}

// maxInstance keeps DefaultListenPort within a valid port number.
const maxInstance = 65535 - 60217

// ValidateInstance rejects an instance number that would push
// DefaultListenPort past a valid port number.
func ValidateInstance(instance int) error {
	if instance < 0 || instance > maxInstance {
		return fmt.Errorf("--instance must be between 0 and %d, got %d", maxInstance, instance)
	}
	return nil
}

// ResolvePath implements the lookup order from
// docs/arch/config-and-lifecycle.md: an explicit --config path always
// wins; otherwise $XDG_CONFIG_HOME/wganchor/<N>.json, then
// /etc/wganchor/<N>.json, first existing file wins. No implicit cwd
// lookup. Returns the winning path, or errNoConfigFound with the list of
// paths that were checked.
func ResolvePath(explicit string, instance int) (path string, checked []string, err error) {
	if explicit != "" {
		info, statErr := os.Stat(explicit) //nolint:gosec // explicit is the operator-supplied --config flag value, not external/untrusted input
		if statErr != nil || info.IsDir() {
			return "", []string{explicit}, fmt.Errorf("%w: %s", errNoConfigFound, explicit)
		}
		return explicit, nil, nil
	}

	var candidates []string
	if userCfgDir, dirErr := os.UserConfigDir(); dirErr == nil {
		candidates = append(candidates, filepath.Join(userCfgDir, "wganchor", fmt.Sprintf("%d.json", instance)))
	}
	candidates = append(candidates, filepath.Join(Dir, fmt.Sprintf("%d.json", instance)))

	for _, candidate := range candidates {
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() { //nolint:gosec // candidate is the operator's --config flag, or $XDG_CONFIG_HOME (via os.UserConfigDir)/etc/wganchor joined with an already-validated int instance number — root's own environment, not external/untrusted input
			return candidate, candidates, nil
		}
	}
	return "", candidates, errNoConfigFound
}

// PathForInstance is the system-daemon config location for instance, per
// docs/arch/config-and-lifecycle.md.
func PathForInstance(instance int) string {
	return filepath.Join(Dir, fmt.Sprintf("%d.json", instance))
}

// Load reads and parses the config at path, refusing to load one that
// isn't mode 0600 (never a config the tool itself wrote otherwise, since
// it may contain a WireGuard private key).
func Load(path string) (*Config, error) {
	info, err := os.Stat(path) //nolint:gosec // path is ResolvePath's result: the operator's --config flag or a fixed candidate directory, not external input
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		return nil, fmt.Errorf("refusing to load config with mode %04o (must be 0600): %s", perm, path)
	}

	data, err := os.ReadFile(path) //nolint:gosec // same path as the os.Stat call above
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}

// Persist writes cfg back to path as JSON, atomically: this file is the
// only copy of a WireGuard private key, so a crash or a full disk
// partway through the write must never leave it truncated or corrupted.
// Written to a temp file in the same directory (so the final rename is on
// the same filesystem) with 0600 set explicitly before the rename, since
// os.WriteFile's perm argument is only honored when creating a new file —
// it never changes an existing file's mode.
func Persist(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ") //nolint:gosec // PrivateKey is deliberately serialized here; the file this writes to is always 0600 (see below)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() //nolint:gosec // tmpPath is generated by os.CreateTemp next to the caller's own path, not external input; no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path) //nolint:gosec // tmpPath is generated by os.CreateTemp next to the caller's own path, not external input
}
