// Command wganchor exposes a VPS's public secondary IP as a
// locally-bindable network interface on a home machine, tunneled over
// WireGuard. See docs/arch/ for the design.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
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
	case "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wganchor <server|client> [--instance N] [--config PATH]")
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

	fmt.Printf("wganchor %s (instance %d)\n", role, *instance)
	fmt.Printf("config: %s\n", path)
	fmt.Printf("%+v\n", cfg.Redacted())
}
