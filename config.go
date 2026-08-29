package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

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
}

// Redacted returns a copy of cfg with PrivateKey masked, safe to print.
func (c Config) Redacted() Config {
	if c.PrivateKey != "" {
		c.PrivateKey = "(redacted)"
	}
	return c
}

var errNoConfigFound = errors.New("no config file found")

// defaultInterfaceName and defaultListenPort implement the uniform
// per-instance formula from docs/arch/wireguard.md: wganchor<N> /
// 60217+N, with N=0 identical to the unnumbered case.
func defaultInterfaceName(instance int) string {
	return fmt.Sprintf("wganchor%d", instance)
}

func defaultListenPort(instance int) int {
	return 60217 + instance
}

// maxInstance keeps defaultListenPort within a valid port number.
const maxInstance = 65535 - 60217

func validateInstance(instance int) error {
	if instance < 0 || instance > maxInstance {
		return fmt.Errorf("--instance must be between 0 and %d, got %d", maxInstance, instance)
	}
	return nil
}

// resolveConfigPath implements the lookup order from
// docs/arch/config-and-lifecycle.md: an explicit --config path always
// wins; otherwise $XDG_CONFIG_HOME/wganchor/<N>.json, then
// /etc/wganchor/<N>.json, first existing file wins. No implicit cwd
// lookup. Returns the winning path, or errNoConfigFound with the list of
// paths that were checked.
func resolveConfigPath(explicit string, instance int) (path string, checked []string, err error) {
	if explicit != "" {
		info, statErr := os.Stat(explicit)
		if statErr != nil || info.IsDir() {
			return "", []string{explicit}, fmt.Errorf("%w: %s", errNoConfigFound, explicit)
		}
		return explicit, nil, nil
	}

	var candidates []string
	if userCfgDir, dirErr := os.UserConfigDir(); dirErr == nil {
		candidates = append(candidates, filepath.Join(userCfgDir, "wganchor", fmt.Sprintf("%d.json", instance)))
	}
	candidates = append(candidates, filepath.Join("/etc/wganchor", fmt.Sprintf("%d.json", instance)))

	for _, candidate := range candidates {
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return candidate, candidates, nil
		}
	}
	return "", candidates, errNoConfigFound
}

// loadConfig reads and parses the config at path, refusing to load one
// that isn't mode 0600 (never a config the tool itself wrote otherwise,
// since it may contain a WireGuard private key).
func loadConfig(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		return nil, fmt.Errorf("refusing to load config with mode %04o (must be 0600): %s", perm, path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &cfg, nil
}
