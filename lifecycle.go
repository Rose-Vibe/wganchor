package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	systemdUnitDir     = "/etc/systemd/system"
	wganchorConfigDir  = "/etc/wganchor"
	wganchorBinaryPath = "/usr/local/bin/wganchor"
)

// configPathForInstance is the system-daemon config location for
// instance, per docs/arch/config-and-lifecycle.md.
func configPathForInstance(instance int) string {
	return filepath.Join(wganchorConfigDir, fmt.Sprintf("%d.json", instance))
}

// skeletonConfig builds the config `install` writes for a fresh instance:
// concrete listen_port/interface_name filled in (never left implicit,
// per docs/arch/wireguard.md), everything the operator must supply by
// hand left blank.
func skeletonConfig(instance int, privateKey string) *Config {
	return &Config{
		PrivateKey:    privateKey,
		ListenPort:    defaultListenPort(instance),
		InterfaceName: defaultInterfaceName(instance),
	}
}

// precheckLifecycle runs the install/uninstall preconditions from
// plan-lifecycle.md before either command touches any state: both must
// either fully happen or not start at all, never partially apply.
func precheckLifecycle() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must be run as root")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found on PATH; only systemd hosts are supported")
	}
	return nil
}

// copyBinaryIfChanged copies the currently-running executable to destPath,
// skipping the copy if the destination already has identical content —
// so re-running install after a rebuild picks up the new binary, but a
// no-op install doesn't needlessly touch /usr/local/bin. Written via a
// temp-file-plus-rename in the destination directory, same reasoning as
// persistConfig: never leave a partially-written binary in place.
func copyBinaryIfChanged(destPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	selfPath, err = filepath.EvalSymlinks(selfPath)
	if err != nil {
		return err
	}
	selfData, err := os.ReadFile(selfPath)
	if err != nil {
		return err
	}

	if destData, err := os.ReadFile(destPath); err == nil && bytes.Equal(destData, selfData) { //nolint:gosec // destPath is always a fixed install-location constant, never external input
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(selfData); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, destPath)
}

// writeUnitIfChanged writes the shared systemd template for role if it's
// missing, or if its content differs from what this binary embeds — the
// template is used by every instance of that role on the machine, so it's
// never *removed* while another instance still depends on it (see
// removeTemplateIfUnused), but it must still track the binary's own
// template: this is exactly how a machine installed before the
// Type=oneshot fix would otherwise keep running the broken Type=simple
// unit through every later `install`, silently, since the file already
// existed and was never touched again.
func writeUnitIfChanged(unitDir, role string) error {
	path := filepath.Join(unitDir, unitFileName(role))
	want := unitTemplateForRole(role)
	if current, err := os.ReadFile(path); err == nil && string(current) == want { //nolint:gosec // unitDir is a fixed constant and role is one of a small enum, never external input
		return nil
	}
	return os.WriteFile(path, []byte(want), 0o644) //nolint:gosec // systemd unit files must be world-readable (0644); this isn't secret material like the 0600 config
}

// writeWatchUnitIfChanged is writeUnitIfChanged's counterpart for the
// watch companion unit's shared template.
func writeWatchUnitIfChanged(unitDir, role string) error {
	path := filepath.Join(unitDir, unitFileName(watchRoleFor(role)))
	want := watchUnitTemplateForRole(role)
	if current, err := os.ReadFile(path); err == nil && string(current) == want { //nolint:gosec // unitDir is a fixed constant and role is one of a small enum, never external input
		return nil
	}
	return os.WriteFile(path, []byte(want), 0o644) //nolint:gosec // systemd unit files must be world-readable (0644); this isn't secret material like the 0600 config
}

// InstallInstance implements `wganchor install <role> --instance N
// [--no-watch]`, per plan-lifecycle.md and plan-reconciliation-watch.md.
// watch defaults to true (on-by-default, matching Tailscale's own
// out-of-the-box resilience) — --no-watch passes false.
func InstallInstance(role string, instance int, watch bool) error {
	if err := precheckLifecycle(); err != nil {
		return err
	}
	if err := copyBinaryIfChanged(wganchorBinaryPath); err != nil {
		return err
	}

	configPath := configPathForInstance(instance)
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(wganchorConfigDir, 0o700); err != nil {
			return err
		}
		if err := persistConfig(skeletonConfig(instance, ""), configPath); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	// EnsureKeys, not a second generate/persist/derive sequence: it's the
	// same security-sensitive key-provisioning path the daemon itself uses
	// on first run (main.go), so there is exactly one place that can get
	// this wrong. Also covers a config that exists but has an empty
	// private_key (e.g. an install interrupted right after the skeleton
	// was written) — a second implementation here previously reached
	// PublicKeyFromPrivate("") in that case, which fails against `wg
	// pubkey` after the binary had already been copied.
	pubKey, _, err := EnsureKeys(cfg, configPath)
	if err != nil {
		return err
	}

	if err := writeUnitIfChanged(systemdUnitDir, role); err != nil {
		return err
	}
	if watch {
		if err := writeWatchUnitIfChanged(systemdUnitDir, role); err != nil {
			return err
		}
	}
	if _, err := runCmd("systemctl", "daemon-reload"); err != nil {
		return err
	}
	unit := unitName(role, instance)
	if _, err := runCmd("systemctl", "enable", unit); err != nil {
		return err
	}
	watchUnit := unitName(watchRoleFor(role), instance)
	if watch {
		// Enabled before the bring-up unit's start below: the watch
		// unit's [Install] WantedBy=<bring-up unit> means enabling it
		// creates the symlink under the bring-up unit's own .wants/
		// directory, so the bring-up unit's start (next) already pulls
		// the watcher up too — no separate `systemctl start` of the
		// watch unit needed.
		if _, err := runCmd("systemctl", "enable", watchUnit); err != nil {
			return err
		}
	} else if err := teardownWatchUnit(role, instance); err != nil {
		// --no-watch on a reinstall of a previously-watcher-enabled
		// instance: the flag describes desired state, so a still-enabled
		// watch unit from an earlier install must be torn down here
		// rather than silently left running.
		return err
	}
	// enable and start are separate calls, not `enable --now`: a fresh
	// skeleton config has no peer_public_key/peer_endpoint/relay_ips yet
	// (left blank for the operator, above), so the immediate start is
	// *expected* to fail on a brand-new instance — that must not make
	// `install` itself report failure, since everything install is
	// actually responsible for (binary, config, unit, enablement) still
	// succeeded. The operator finishes the config, then starts the
	// service themselves (or reruns `install`, which is idempotent).
	_, startErr := runCmd("systemctl", "start", unit)

	fmt.Printf("installed wganchor %s instance %d\n", role, instance)
	fmt.Printf("public key: %s\n", pubKey)
	fmt.Printf("config: %s\n", configPath)
	if watch {
		fmt.Printf("reconciliation watch enabled (%s) — pass --no-watch to opt out\n", watchUnit)
	}
	if startErr != nil {
		fmt.Printf("note: %s did not start yet (%v) — fill in peer_public_key/", unit, startErr)
		if role == "client" {
			fmt.Print("peer_endpoint/")
		}
		fmt.Printf("relay_ips in %s, then `systemctl start %s`\n", configPath, unit)
	}
	if role == "server" {
		fmt.Printf("reminder: wganchor does not manage firewall or sysctl state — open UDP port %d "+
			"inbound, allow forwarding both directions between this host's public interface and %s, "+
			"and confirm net.ipv4.ip_forward=1.\n", cfg.ListenPort, cfg.InterfaceName)
	}
	return nil
}

// disableUnit runs `systemctl disable --now unit`, treating "this unit
// was never installed" as a successful no-op rather than an error, per
// plan-lifecycle.md's "safe to re-run" requirement.
//
// It also clears a lingering "failed" record for the unit (harmless but
// confusing: `Type=oneshot`'s Restart=on-failure means an instance whose
// config was never finished — see InstallInstance's enable/start split —
// often ends its life in ActiveState=failed; systemd keeps showing that in
// `systemctl list-units --all` until reset, even though UnitFileState is
// already correctly `disabled`). Best-effort: reset-failed's own failure
// never fails the uninstall.
func disableUnit(unit string) error {
	cmd := exec.Command("systemctl", "disable", "--now", unit) //nolint:gosec // "systemctl" is a fixed binary; unit is internally constructed by unitName, not external input
	out, err := cmd.CombinedOutput()
	if err != nil && !isUnitNotInstalledOutput(string(out)) {
		return fmt.Errorf("systemctl disable --now %s: %w: %s", unit, err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("systemctl", "reset-failed", unit).Run() //nolint:gosec // same as above; best-effort, per comment above
	return nil
}

// isUnitNotInstalledOutput reports whether combined `systemctl` output
// indicates "this unit was never installed" rather than a real failure —
// extracted as a plain string predicate (rather than left inline in
// disableUnit) so it's directly testable against sample systemctl output,
// with no systemctl invocation needed in tests.
func isUnitNotInstalledOutput(output string) bool {
	combined := strings.ToLower(output)
	return strings.Contains(combined, "does not exist") || strings.Contains(combined, "no such file")
}

// otherEnabledInstanceUnits globs every `*.wants/` directory under
// systemdDir for enabled instances of role other than excludeUnit — used
// to decide whether the shared template file is still in use before
// removing it. The bring-up unit's own enablement symlinks live under
// `multi-user.target.wants/` (confirmed empirically to be the reliable
// source of truth for "which instances are actually enabled" —
// `systemctl list-unit-files` was tried first and rejected: for a
// templated unit it only ever lists the shared template itself, state
// `indirect`, never the per-instance instantiated units). The watch
// companion unit's [Install] section instead points `WantedBy=` at the
// bring-up unit itself, so its enablement symlinks land under a
// different, per-instance directory
// (`wganchor-<role>@<N>.service.wants/`) — hence globbing every
// `*.wants/` dir rather than a single hardcoded one, a backward-
// compatible generalization since the bring-up unit's existing
// `multi-user.target.wants/` location still matches the wider glob
// unchanged. systemdDir is a parameter (rather than always
// systemdUnitDir) so this stays testable against a fixture directory
// tree.
func otherEnabledInstanceUnits(systemdDir, role, excludeUnit string) ([]string, error) {
	pattern := fmt.Sprintf("wganchor-%s@*.service", role)
	matches, err := filepath.Glob(filepath.Join(systemdDir, "*.wants", pattern))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var others []string
	for _, m := range matches {
		name := filepath.Base(m)
		if name == excludeUnit || seen[name] {
			continue
		}
		seen[name] = true
		others = append(others, name)
	}
	sort.Strings(others)
	return others, nil
}

// removeTemplateIfUnused removes the shared systemd template for role if
// no other enabled instance of that role remains on the machine —
// uninstalling one instance must never break another running instance of
// the same role.
func removeTemplateIfUnused(role string, excludeUnit string) error {
	others, err := otherEnabledInstanceUnits(systemdUnitDir, role, excludeUnit)
	if err != nil {
		return err
	}
	if len(others) > 0 {
		return nil
	}
	path := filepath.Join(systemdUnitDir, unitFileName(role))
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	_, err = runCmd("systemctl", "daemon-reload")
	return err
}

// teardownWatchUnit stops, disables, and removes the watch companion
// unit for role/instance, and its shared template if no other instance
// still uses it. Used both by uninstall (always, regardless of whether
// --no-watch was passed at install time — uninstall doesn't need to know
// how the watch unit got there, just that it might be there) and by
// install --no-watch on a reinstall of a previously-watcher-enabled
// instance (a flag describes desired state, so a still-enabled watch
// unit from an earlier install must not be silently left running).
func teardownWatchUnit(role string, instance int) error {
	watchUnit := unitName(watchRoleFor(role), instance)
	if err := disableUnit(watchUnit); err != nil {
		return err
	}
	return removeTemplateIfUnused(watchRoleFor(role), watchUnit)
}

// deleteInterfaceIfExists tears down a WireGuard interface as part of
// --purge, tolerating "already gone" as success.
func deleteInterfaceIfExists(name string) error {
	if !interfaceExists(name) {
		return nil
	}
	_, err := runCmd("ip", "link", "delete", name)
	return err
}

// purgeClientPolicyRules removes any leftover `ip rule` entries for this
// client instance's policy-routing table (docs/arch/wireguard.md's
// table/priority formula). These rules aren't bound to the wganchor<N>
// interface — deleting the interface leaves them in the kernel forever,
// since nothing else ever revisits them once the config that recorded
// their relay IPs is gone. Read from live kernel state via the same
// parseIPRuleShowForTable ReconcileClientRouting uses, rather than the
// config's relay_ips, so purge still cleans up correctly even if relay_ips
// had already drifted from what's actually in the kernel.
func purgeClientPolicyRules(instance int) error {
	table := tableForInstance(instance)
	out, err := runCmd("ip", "rule", "show")
	if err != nil {
		return err
	}
	for _, ip := range parseIPRuleShowForTable(out, table) {
		if _, err := runCmd("ip", "rule", "del", "from", ip, "table", strconv.Itoa(table)); err != nil {
			return err
		}
	}
	return nil
}

// UninstallInstance implements `wganchor uninstall <role> --instance N
// [--purge]`, per plan-lifecycle.md.
func UninstallInstance(role string, instance int, purge bool) error {
	if err := precheckLifecycle(); err != nil {
		return err
	}

	unit := unitName(role, instance)
	if err := disableUnit(unit); err != nil {
		return err
	}
	if err := removeTemplateIfUnused(role, unit); err != nil {
		return err
	}
	if err := teardownWatchUnit(role, instance); err != nil {
		return err
	}

	if !purge {
		return nil
	}

	configPath := configPathForInstance(instance)
	interfaceName := defaultInterfaceName(instance)
	if cfg, err := loadConfig(configPath); err == nil && cfg.InterfaceName != "" {
		interfaceName = cfg.InterfaceName
	}

	// Interface (and, for a client, its policy-routing rules) torn down
	// before the config is removed: the config is the only record of a
	// non-default interface_name, so if teardown fails partway through, a
	// retry must still be able to find the right interface rather than
	// falling back to defaultInterfaceName and losing track of it.
	if role == "client" {
		if err := purgeClientPolicyRules(instance); err != nil {
			return err
		}
	}
	// Bring-up only ever applies a firewall on the client role
	// (docs/arch/firewall.md's scope), but the `firewall` subcommands
	// are deliberately role-agnostic — an operator can run `firewall
	// enable --instance N` against a server-role instance too. So this
	// teardown isn't gated on role: it's already tolerant of "never
	// enabled" (no `firewall` subcommand ever run, `nft` never
	// installed, or already `disable`d), making it a graceful no-op in
	// every case where there was nothing to remove.
	if err := disableInstanceFirewall(instance); err != nil {
		return err
	}
	if err := deleteInterfaceIfExists(interfaceName); err != nil {
		return err
	}

	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if entries, err := os.ReadDir(wganchorConfigDir); err == nil && len(entries) == 0 {
		_ = os.Remove(wganchorConfigDir) // best-effort: leaving an empty dir behind isn't worth failing the uninstall over
	}
	return nil
}
