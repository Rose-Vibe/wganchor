// Command wganchor exposes a VPS's public secondary IP as a
// locally-bindable network interface on a home machine, tunneled over
// WireGuard. See docs/arch/ for the design.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	role := os.Args[1]
	switch role {
	case "server", "client":
		run(role, os.Args[2:])
	case "watch":
		runWatchCmd(os.Args[2:])
	case "install":
		runInstall(os.Args[2:])
	case "uninstall":
		runUninstall(os.Args[2:])
	case "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wganchor <server|client> [--instance N] [--config PATH]")
	fmt.Fprintln(os.Stderr, "       wganchor watch <server|client> [--instance N] [--config PATH] [--interval DURATION]")
	fmt.Fprintln(os.Stderr, "       wganchor install <server|client> [--instance N] [--no-watch]")
	fmt.Fprintln(os.Stderr, "       wganchor uninstall <server|client> [--instance N] [--purge]")
}

// runWatchCmd parses `wganchor watch <server|client> [--instance N]
// [--config PATH] [--interval DURATION]` and runs the reconciliation
// watch loop (watch.go). Shares resolveConfigPath with run() so it picks
// up the same config, for parity with server/client rather than a
// separate lookup mechanism.
func runWatchCmd(args []string) {
	role, rest := parseLifecycleArgs("watch", "[--instance N] [--config PATH] [--interval DURATION]", args)
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number, selects wganchor<N>/<N>.json (default 0)")
	configPath := fs.String("config", "", "explicit path to config file, overrides the default lookup")
	interval := fs.Duration("interval", 5*time.Minute, "periodic reconciliation backstop interval")
	fs.Parse(rest)

	if err := validateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: %v\n", err)
		os.Exit(1)
	}

	path, checked, err := resolveConfigPath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: no config found for instance %d\n", *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		os.Exit(1)
	}

	if err := runWatch(role, *instance, path, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: %v\n", err)
		os.Exit(1)
	}
}

// runInstall and runUninstall parse the shared `<role> [--instance N]`
// shape, then delegate to InstallInstance/UninstallInstance (lifecycle.go).
func runInstall(args []string) {
	role, rest := parseLifecycleArgs("install", "[--instance N] [--no-watch]", args)
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	noWatch := fs.Bool("no-watch", false, "don't install/enable the reconciliation watch companion (on by default)")
	fs.Parse(rest)

	if err := validateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor install: %v\n", err)
		os.Exit(1)
	}
	if err := InstallInstance(role, *instance, !*noWatch); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor install: %v\n", err)
		os.Exit(1)
	}
}

func runUninstall(args []string) {
	role, rest := parseLifecycleArgs("uninstall", "[--instance N] [--purge]", args)
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	purge := fs.Bool("purge", false, "also remove the config and interface for this instance")
	fs.Parse(rest)

	if err := validateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor uninstall: %v\n", err)
		os.Exit(1)
	}
	if err := UninstallInstance(role, *instance, *purge); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor uninstall: %v\n", err)
		os.Exit(1)
	}
}

// parseLifecycleArgs extracts the required, positional <server|client>
// role argument shared by install/uninstall/watch, exiting with a usage
// error if it's missing or invalid. flagsUsage documents this specific
// command's own flags (each command's set differs — e.g. watch's
// --config/--interval vs. install's --no-watch), so the error message
// doesn't silently fall out of sync with what the command actually
// accepts, the way a single hardcoded "[--instance N]" string did.
func parseLifecycleArgs(cmd, flagsUsage string, args []string) (role string, rest []string) {
	if len(args) < 1 || (args[0] != "server" && args[0] != "client") {
		fmt.Fprintf(os.Stderr, "usage: wganchor %s <server|client> %s\n", cmd, flagsUsage)
		os.Exit(1)
	}
	return args[0], args[1:]
}

func run(role string, args []string) {
	fs := flag.NewFlagSet(role, flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number, selects wganchor<N>/<N>.json (default 0)")
	configPath := fs.String("config", "", "explicit path to config file, overrides the default lookup")
	fs.Parse(args)

	if err := validateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	ifaceDefault := defaultInterfaceName(*instance)
	portDefault := defaultListenPort(*instance)

	path, checked, err := resolveConfigPath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: no config found for instance %d\n", role, *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		fmt.Fprintf(os.Stderr, "  defaults for this instance: interface_name=%s listen_port=%d\n", ifaceDefault, portDefault)
		fmt.Fprintf(os.Stderr, "  create one at a path above, or pass --config\n")
		os.Exit(1)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	// interface_name/listen_port default to the per-instance formula when
	// absent from the config, matching wireguard.md's "defaults to
	// wganchor<N> [...], overridable" wording — a config missing them
	// would otherwise reach `ip link add ""` (an opaque ip(8) error) or
	// `wg set ... listen-port 0` (silently binds a random port instead of
	// the documented one), rather than failing the way the pre-flight
	// validation below is meant to.
	if cfg.InterfaceName == "" {
		cfg.InterfaceName = ifaceDefault
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = portDefault
	}

	// Key self-provisioning happens unconditionally on load, before the
	// peer_public_key check below: each side is expected to be able to
	// generate its own keypair and print the public key locally, even
	// before it knows the other side's key — that's the manual exchange
	// step (docs/arch/wireguard.md), not something peer_public_key being
	// blank should block.
	pubKey, generated, err := EnsureKeys(cfg, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}
	if generated {
		fmt.Printf("generated a new keypair; public key: %s\n", pubKey)
	}

	if err := ValidateConfig(cfg, role); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	name := cfg.InterfaceName
	if err := EnsureInterface(name); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}
	if err := ConfigureInterface(cfg, role, name); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	if role == "server" {
		if _, err := ReconcileServerRoutes(name, cfg.RelayIPs); err != nil {
			fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
			os.Exit(1)
		}
		if ok, ipfErr := CheckIPForward(); ipfErr == nil && !ok {
			fmt.Fprintln(os.Stderr, ipForwardWarning)
		}
	} else {
		if _, err := ReconcileClientRouting(name, cfg.RelayIPs, *instance); err != nil {
			fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
			os.Exit(1)
		}
	}

	fmt.Printf("wganchor %s (instance %d): %s up, peer configured, relay_ips=%v\n", role, *instance, name, cfg.RelayIPs)
}
