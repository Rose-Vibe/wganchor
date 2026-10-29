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

	"github.com/Rose-Vibe/wganchor/internal/config"
	"github.com/Rose-Vibe/wganchor/internal/firewall"
	"github.com/Rose-Vibe/wganchor/internal/lifecycle"
	"github.com/Rose-Vibe/wganchor/internal/pair"
	"github.com/Rose-Vibe/wganchor/internal/relay"
	"github.com/Rose-Vibe/wganchor/internal/routing"
	"github.com/Rose-Vibe/wganchor/internal/watch"
	"github.com/Rose-Vibe/wganchor/internal/wireguard"
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
	case "firewall":
		runFirewallCmd(os.Args[2:])
	case "relay":
		runRelayCmd(os.Args[2:])
	case "pair":
		runPairCmd(os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "usage: wganchor <server|client> [--instance N] [--config PATH] [--no-firewall]")
	fmt.Fprintln(os.Stderr, "       wganchor watch <server|client> [--instance N] [--config PATH] [--interval DURATION]")
	fmt.Fprintln(os.Stderr, "       wganchor install <server|client> [--instance N] [--no-watch]")
	fmt.Fprintln(os.Stderr, "       wganchor uninstall <server|client> [--instance N] [--purge]")
	fmt.Fprintln(os.Stderr, "       wganchor firewall enable|allow|deny|disable --instance N [--port <port|start-end>/<tcp|udp|both>]")
	fmt.Fprintln(os.Stderr, "       wganchor relay add|remove <server|client> --instance N --ip <ipv4>")
	fmt.Fprintln(os.Stderr, "       wganchor pair pubkey --instance N")
	fmt.Fprintln(os.Stderr, "       wganchor pair peer --instance N --public-key KEY [--endpoint HOST:PORT]")
	fmt.Fprintln(os.Stderr, "       wganchor pair run --instance N --remote TARGET [--remote-instance M] [--remote-exec TEMPLATE] [--endpoint HOST:PORT]")
}

// runWatchCmd parses `wganchor watch <server|client> [--instance N]
// [--config PATH] [--interval DURATION]` and runs the reconciliation
// watch loop (internal/watch). Shares config.ResolvePath with run() so it
// picks up the same config, for parity with server/client rather than a
// separate lookup mechanism.
func runWatchCmd(args []string) {
	role, rest := parseLifecycleArgs("watch", "[--instance N] [--config PATH] [--interval DURATION]", args)
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number, selects wganchor<N>/<N>.json (default 0)")
	configPath := fs.String("config", "", "explicit path to config file, overrides the default lookup")
	interval := fs.Duration("interval", 5*time.Minute, "periodic reconciliation backstop interval")
	_ = fs.Parse(rest) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: %v\n", err)
		os.Exit(1)
	}

	path, checked, err := config.ResolvePath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: no config found for instance %d\n", *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		os.Exit(1)
	}

	if err := watch.Run(role, *instance, path, *interval); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor watch: %v\n", err)
		os.Exit(1)
	}
}

// runFirewallCmd parses `wganchor firewall <enable|allow|deny|disable>
// --instance N [--port <port|start-end>/<tcp|udp|both>]` and delegates
// to the Firewall* functions (internal/firewall). No --role flag —
// resolving the interface only needs the instance number, and the
// firewall mechanism doesn't care which role created the interface
// (docs/arch/firewall.md). `/both` is expanded into its tcp+udp pair
// here, at the CLI layer, before either ever reaches ParsePortSpec or a
// Firewall* call — see firewall.ExpandBothProto.
func runFirewallCmd(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: wganchor firewall <enable|allow|deny|disable> --instance N [--port <port|start-end>/<tcp|udp|both>]")
		os.Exit(1)
	}
	sub := args[0]
	if sub != "enable" && sub != "allow" && sub != "deny" && sub != "disable" {
		fmt.Fprintln(os.Stderr, "usage: wganchor firewall <enable|allow|deny|disable> --instance N [--port <port|start-end>/<tcp|udp|both>]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("firewall "+sub, flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	port := fs.String("port", "", "port spec <port|start-end>/<tcp|udp|both>, e.g. 8080/tcp, 8000-8010/udp, 53/both (required for allow/deny)")
	_ = fs.Parse(args[1:]) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor firewall %s: %v\n", sub, err)
		os.Exit(1)
	}

	var cmdErr error
	switch sub {
	case "enable":
		cmdErr = firewall.Enable(*instance)
	case "disable":
		cmdErr = firewall.Disable(*instance)
	case "allow", "deny":
		if *port == "" {
			fmt.Fprintf(os.Stderr, "wganchor firewall %s: --port is required, e.g. --port 8080/tcp\n", sub)
			os.Exit(1)
		}
		specs := firewall.ExpandBothProto(*port)
		for i, spec := range specs {
			start, end, proto, perr := firewall.ParsePortSpec(spec)
			if perr != nil {
				fmt.Fprintf(os.Stderr, "wganchor firewall %s: %v\n", sub, perr)
				os.Exit(1)
			}
			if sub == "allow" {
				cmdErr = firewall.Allow(*instance, start, end, proto)
			} else {
				cmdErr = firewall.Deny(*instance, start, end, proto)
			}
			if cmdErr != nil {
				// A /both spec expands to two independent, individually
				// idempotent calls (firewall.ExpandBothProto) — if the
				// second one fails, the first already succeeded and
				// persisted. Say so, so the operator doesn't assume
				// *nothing* happened: a plain re-run of the same command
				// converges correctly either way.
				if i > 0 {
					fmt.Fprintf(os.Stderr, "wganchor firewall %s: %s already applied; re-run to retry the rest\n", sub, specs[i-1])
				}
				break
			}
		}
	}

	if cmdErr != nil {
		fmt.Fprintf(os.Stderr, "wganchor firewall %s: %v\n", sub, cmdErr)
		os.Exit(1)
	}
	fmt.Printf("wganchor firewall %s: instance %d done\n", sub, *instance)
}

// runRelayCmd parses `wganchor relay <add|remove> <server|client>
// --instance N --ip <ipv4>` and delegates to relay.Add/Remove.
// Unlike firewall, role IS a required positional argument here — the two
// roles' live-apply mechanisms genuinely differ (see
// docs/sprints/relay-and-firewall-ops/plan-relay-management.md's Goal
// section), the same reason install/uninstall/watch already take role
// positionally.
func runRelayCmd(args []string) {
	const usageLine = "usage: wganchor relay <add|remove> <server|client> --instance N --ip <ipv4>"
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usageLine)
		os.Exit(1)
	}
	sub := args[0]
	if sub != "add" && sub != "remove" {
		fmt.Fprintln(os.Stderr, usageLine)
		os.Exit(1)
	}

	role, rest := parseLifecycleArgs("relay "+sub, "--instance N --ip <ipv4>", args[1:])
	fs := flag.NewFlagSet("relay "+sub, flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	ip := fs.String("ip", "", "relay IPv4 address (required)")
	_ = fs.Parse(rest) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor relay %s: %v\n", sub, err)
		os.Exit(1)
	}
	if *ip == "" {
		fmt.Fprintf(os.Stderr, "wganchor relay %s: --ip is required\n", sub)
		os.Exit(1)
	}

	var cmdErr error
	if sub == "add" {
		cmdErr = relay.Add(role, *instance, *ip)
	} else {
		cmdErr = relay.Remove(role, *instance, *ip)
	}
	if cmdErr != nil {
		fmt.Fprintf(os.Stderr, "wganchor relay %s: %v\n", sub, cmdErr)
		os.Exit(1)
	}
	fmt.Printf("wganchor relay %s: instance %d done (relay_ip=%s)\n", sub, *instance, *ip)
}

// runPairCmd dispatches `wganchor pair pubkey|peer|run`. See
// docs/sprints/pairing/plan-pairing.md for the full design: pair pubkey
// and pair peer are plain, scriptable primitives a human could also run
// by hand (including manually after ssh-ing in themselves); pair run
// automates calling those same two commands against a remote target.
func runPairCmd(args []string) {
	const usageLine = "usage: wganchor pair <pubkey|peer|run> --instance N [flags] (see --help)"
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, usageLine)
		os.Exit(1)
	}
	switch args[0] {
	case "pubkey":
		runPairPubkeyCmd(args[1:])
	case "peer":
		runPairPeerCmd(args[1:])
	case "run":
		runPairRunCmd(args[1:])
	default:
		fmt.Fprintln(os.Stderr, usageLine)
		os.Exit(1)
	}
}

// runPairPubkeyCmd prints exactly the instance's public key on stdout —
// a scripting primitive, both for a human's own script and for
// runPairRunCmd's remote invocation. Any operational message (e.g. "a
// new keypair was generated") is pair.Pubkey's job to send to stderr
// instead, never stdout.
func runPairPubkeyCmd(args []string) {
	fs := flag.NewFlagSet("pair pubkey", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	configPath := fs.String("config", "", "explicit path to config file, overrides the default lookup")
	_ = fs.Parse(args) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair pubkey: %v\n", err)
		os.Exit(1)
	}
	path, checked, err := config.ResolvePath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair pubkey: no config found for instance %d\n", *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		os.Exit(1)
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair pubkey: %v\n", err)
		os.Exit(1)
	}
	pub, err := pair.Pubkey(cfg, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair pubkey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(pub)
}

// runPairPeerCmd writes --public-key (and --endpoint, if given) as this
// instance's peer identity.
func runPairPeerCmd(args []string) {
	fs := flag.NewFlagSet("pair peer", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	configPath := fs.String("config", "", "explicit path to config file, overrides the default lookup")
	publicKey := fs.String("public-key", "", "the peer's WireGuard public key (required)")
	endpoint := fs.String("endpoint", "", "the peer's host:port, e.g. vps.example.com:60217 (optional)")
	_ = fs.Parse(args) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair peer: %v\n", err)
		os.Exit(1)
	}
	if *publicKey == "" {
		fmt.Fprintln(os.Stderr, "wganchor pair peer: --public-key is required")
		os.Exit(1)
	}
	path, checked, err := config.ResolvePath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair peer: no config found for instance %d\n", *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		os.Exit(1)
	}
	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair peer: %v\n", err)
		os.Exit(1)
	}
	if err := pair.Peer(cfg, path, *publicKey, *endpoint, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair peer: %v\n", err)
		os.Exit(1)
	}
}

// runPairRunCmd is the pair-exchange orchestrator: fetches this
// instance's pubkey and --remote's pubkey (via --remote-exec, default
// "ssh {}"), and writes each as the other's peer — see pair.Run.
func runPairRunCmd(args []string) {
	fs := flag.NewFlagSet("pair run", flag.ExitOnError)
	instance := fs.Int("instance", 0, "local instance number (default 0)")
	remoteInstance := fs.Int("remote-instance", -1, "remote instance number (if omitted: same as --instance, EXCEPT this is refused when --config is also given — see --help)")
	remote := fs.String("remote", "", "remote target passed to --remote-exec's {} placeholder, e.g. user@vps.example.com (required)")
	remoteExec := fs.String("remote-exec", "ssh {}", `remote execution command template; must contain exactly one "{}" placeholder for --remote's value`)
	endpoint := fs.String("endpoint", "", "override the derived WireGuard peer_endpoint for the local side")
	configPath := fs.String("config", "", "explicit path to the LOCAL config file, overrides the default lookup (the remote side always uses its own default lookup)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wganchor pair run --instance N --remote TARGET [flags]")
		fs.PrintDefaults()
		fmt.Fprint(os.Stderr, `
notes:
  - pair run only ever writes config file fields (peer_public_key,
    peer_endpoint) on both sides. It never calls "wg set" or restarts
    anything — run "wganchor server"/"wganchor client" again afterward
    to apply a newly-paired peer to the live WireGuard interface.
  - the derived --endpoint (used when --endpoint is omitted) is a guess:
    it assumes the remote's listen_port matches the standard formula and
    that --remote is a directly-dialable host, not an ssh_config Host
    alias. Pass --endpoint explicitly if either assumption is wrong.
  - a partial failure is recovered by re-running pair run, not by an
    automatic rollback: every step it performs is independently
    idempotent, so simply fixing whatever failed and re-running
    converges both sides correctly.
  - for a non-root SSH login needing sudo on the remote, --remote-exec
    "ssh {} sudo" only works if the remote sudo does not require a
    password (NOPASSWD): an interactive sudo password prompt cannot be
    answered through pair run's non-interactive remote-exec plumbing.
  - --remote-instance defaults to --instance's value, EXCEPT this
    inference is refused (and --remote-instance becomes required) when
    --config is also given: --config makes --instance's number a pure
    label for the local lookup, with no bearing on which remote config
    the default would select — see docs/sprints/pairing/plan-pairing.md.
`)
	}
	_ = fs.Parse(args) // flag.ExitOnError already exits the process on a parse failure

	remoteInstanceSet, configSet := false, false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "remote-instance":
			remoteInstanceSet = true
		case "config":
			configSet = true
		}
	})

	if *remote == "" {
		fmt.Fprintln(os.Stderr, "wganchor pair run: --remote is required")
		os.Exit(1)
	}
	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair run: %v\n", err)
		os.Exit(1)
	}
	if configSet && !remoteInstanceSet {
		fmt.Fprintln(os.Stderr, "wganchor pair run: --remote-instance is required when --config is given (see --help)")
		os.Exit(1)
	}
	ri := *remoteInstance
	if !remoteInstanceSet {
		ri = *instance
	}
	if err := config.ValidateInstance(ri); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair run: --remote-instance: %v\n", err)
		os.Exit(1)
	}

	err := pair.Run(pair.RunOptions{
		Instance:       *instance,
		RemoteInstance: ri,
		Remote:         *remote,
		RemoteExec:     *remoteExec,
		Endpoint:       *endpoint,
		ConfigPath:     *configPath,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor pair run: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wganchor pair run: instance %d paired with %s (remote instance %d)\n", *instance, *remote, ri)
}

// runInstall and runUninstall parse the shared `<role> [--instance N]`
// shape, then delegate to lifecycle.InstallInstance/UninstallInstance.
func runInstall(args []string) {
	role, rest := parseLifecycleArgs("install", "[--instance N] [--no-watch]", args)
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	noWatch := fs.Bool("no-watch", false, "don't install/enable the reconciliation watch companion (on by default)")
	_ = fs.Parse(rest) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor install: %v\n", err)
		os.Exit(1)
	}
	if err := lifecycle.InstallInstance(role, *instance, !*noWatch); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor install: %v\n", err)
		os.Exit(1)
	}
}

func runUninstall(args []string) {
	role, rest := parseLifecycleArgs("uninstall", "[--instance N] [--purge]", args)
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	instance := fs.Int("instance", 0, "instance number (default 0)")
	purge := fs.Bool("purge", false, "also remove the config and interface for this instance")
	_ = fs.Parse(rest) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor uninstall: %v\n", err)
		os.Exit(1)
	}
	if err := lifecycle.UninstallInstance(role, *instance, *purge); err != nil {
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
	noFirewall := fs.Bool("no-firewall", false,
		"skip enabling the default client-side firewall for this invocation only — an explicit opt-out "+
			"of a security default; `wganchor firewall disable` is the durable opt-out that survives a reboot")
	_ = fs.Parse(args) // flag.ExitOnError already exits the process on a parse failure

	if err := config.ValidateInstance(*instance); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	ifaceDefault := config.DefaultInterfaceName(*instance)
	portDefault := config.DefaultListenPort(*instance)

	path, checked, err := config.ResolvePath(*configPath, *instance)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: no config found for instance %d\n", role, *instance)
		fmt.Fprintf(os.Stderr, "  checked: %s\n", strings.Join(checked, ", "))
		fmt.Fprintf(os.Stderr, "  defaults for this instance: interface_name=%s listen_port=%d\n", ifaceDefault, portDefault)
		fmt.Fprintf(os.Stderr, "  create one at a path above, or pass --config\n")
		os.Exit(1)
	}

	cfg, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	// interface_name/listen_port default to the per-instance formula when
	// absent from the config (config.ResolveRuntimeDefaults), matching
	// wireguard.md's "defaults to wganchor<N> [...], overridable" wording
	// — a config missing them would otherwise reach `ip link add ""` (an
	// opaque ip(8) error) or `wg set ... listen-port 0` (silently binds a
	// random port instead of the documented one), rather than failing the
	// way the pre-flight validation below is meant to.
	cfg.InterfaceName, cfg.ListenPort = config.ResolveRuntimeDefaults(cfg, *instance)

	// Key self-provisioning happens unconditionally on load, before the
	// peer_public_key check below: each side is expected to be able to
	// generate its own keypair and print the public key locally, even
	// before it knows the other side's key — that's the manual exchange
	// step (docs/arch/wireguard.md), not something peer_public_key being
	// blank should block.
	pubKey, generated, err := wireguard.EnsureKeys(cfg, path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}
	if generated {
		fmt.Printf("generated a new keypair; public key: %s\n", pubKey)
	}

	if err := config.ValidateConfig(cfg, role); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	name := cfg.InterfaceName
	created, err := wireguard.EnsureInterface(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}
	if err := wireguard.ConfigureInterface(cfg, role, name); err != nil {
		fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
		os.Exit(1)
	}

	if role == "server" {
		if _, err := routing.ReconcileServerRoutes(name, cfg.RelayIPs); err != nil {
			fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
			os.Exit(1)
		}
		if ok, ipfErr := routing.CheckIPForward(); ipfErr == nil && !ok {
			fmt.Fprintln(os.Stderr, routing.IPForwardWarning)
		}
	} else {
		// Client-side only, per docs/arch/firewall.md's scope: the
		// server's own VPS firewall (ufw, forwarding rules) is out of
		// scope and untouched here; the server also doesn't locally bind
		// relay IPs at all (it only routes them), so an input-hook
		// scaffold on its wganchor<N> interface would have nothing
		// meaningful to filter. --no-firewall is a one-off, this-
		// invocation-only override; `firewall disable` (cfg.DisableFirewall)
		// is the durable, persisted opt-out.
		//
		// Applied BEFORE ReconcileClientRouting binds the relay IP to
		// name (ip addr replace, below): the scaffold only needs the
		// interface's *name*, not its existence — iifname is a string
		// match — so ensuring it first means a firewall failure (nft
		// missing, a real nft error) exits before the public relay IP is
		// ever live on the host, never after. Reversing this order would
		// leave a real, if brief, unfiltered window on every bring-up,
		// and on any firewall failure that window would never close.
		firewallActive := !cfg.DisableFirewall && !*noFirewall
		if firewallActive {
			if !firewall.NftAvailable() {
				fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, firewall.ErrNftMissing)
				os.Exit(1)
			}
			if err := firewall.EnsureScaffold(name, *instance); err != nil {
				fmt.Fprintf(os.Stderr, "wganchor %s: firewall: %v\n", role, err)
				os.Exit(1)
			}
			if err := firewall.ApplyAllowedPorts(*instance, cfg.FirewallAllowedPorts); err != nil {
				fmt.Fprintf(os.Stderr, "wganchor %s: firewall: %v\n", role, err)
				os.Exit(1)
			}
		}

		if _, err := routing.ReconcileClientRouting(name, cfg.RelayIPs, *instance); err != nil {
			fmt.Fprintf(os.Stderr, "wganchor %s: %v\n", role, err)
			os.Exit(1)
		}

		if created && firewallActive {
			fmt.Printf("wganchor: new interface %s — a default-deny firewall was enabled on it automatically.\n", name)
			if len(cfg.FirewallAllowedPorts) == 0 {
				fmt.Printf("No inbound ports are open yet. To expose a service: wganchor firewall allow --instance %d --port 8080/tcp\n", *instance)
			} else {
				fmt.Printf("Allowed inbound ports (restored from config): %s\n", strings.Join(cfg.FirewallAllowedPorts, ", "))
			}
			fmt.Printf("To turn this off for this instance:                wganchor firewall disable --instance %d\n", *instance)
			fmt.Println("(Firewall state is re-applied on every bring-up, including after a reboot, so allowed ports persist.)")
		}
	}

	fmt.Printf("wganchor %s (instance %d): %s up, peer configured, relay_ips=%v\n", role, *instance, name, cfg.RelayIPs)
}
