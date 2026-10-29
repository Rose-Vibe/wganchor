// Package pair implements `wganchor pair pubkey|peer|run`: exchanging
// WireGuard public keys between two wganchor instances, per
// docs/sprints/pairing/plan-pairing.md.
package pair

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Rose-Vibe/wganchor/internal/config"
	"github.com/Rose-Vibe/wganchor/internal/wireguard"
)

// wgKeyLen is the raw byte length of a WireGuard Curve25519 key (private
// or public — validatePublicKeyFormat's shape check can't tell them
// apart, though looksLikePrivateKey's clamping-based heuristic partially
// can).
const wgKeyLen = 32

// validatePublicKeyFormat reports whether key is shaped like a WireGuard
// key: standard base64 encoding a 32-byte value, matching what
// wireguard.GenerateKeypair/PublicKeyFromPrivate produce. This is a
// format check only — it cannot, by itself, tell a public key from a
// private one (see looksLikePrivateKey for a separate heuristic that
// helps with that specific mistake). Checked before writing a peer (pair
// peer) and before placing a key into a remote-exec argv (pair run) —
// the base64 alphabet (A-Za-z0-9+/=) contains no shell metacharacters,
// so a key that passes this check can never inject anything into a
// remote command line built from it.
func validatePublicKeyFormat(key string) error {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid public key %q: not valid base64: %w", key, err)
	}
	if len(decoded) != wgKeyLen {
		return fmt.Errorf("invalid public key %q: decodes to %d bytes, want %d", key, len(decoded), wgKeyLen)
	}
	return nil
}

// looksLikePrivateKey heuristically flags a value that is very likely a
// WireGuard *private* key passed where a public key was expected — the
// most common real-world `pair peer` mistake (pasting the wrong line out
// of a config). `wg genkey` clamps every private key it produces: the
// first byte is always a multiple of 8, and the last byte's top two bits
// are always 0b01. Public keys have no such structure, so a genuine
// public key satisfies both conditions only by chance (~1/16 of the
// time) — too high a false-positive rate to hard-reject on, but a fine
// basis for a stderr warning rather than a rejection.
func looksLikePrivateKey(key string) bool {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(decoded) != wgKeyLen {
		return false
	}
	return decoded[0]%8 == 0 && decoded[wgKeyLen-1]&0xC0 == 0x40
}

// validateEndpoint reports whether endpoint is a well-formed host:port,
// per internal/config's fail-fast posture — ValidateConfig itself only
// checks non-emptiness, so this catches a malformed value here instead
// of surfacing later as an opaque wg/dial error. net.SplitHostPort alone
// only validates the split syntax (it accepts a non-numeric port, e.g.
// "host:abc"), so the port is additionally parsed as an integer in
// range, matching internal/firewall's ParsePortSpec's existing precedent
// for this exact class of check.
func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint %q: want host:port: %w", endpoint, err)
	}
	if host == "" {
		return fmt.Errorf("invalid endpoint %q: host is empty", endpoint)
	}
	if p, convErr := strconv.Atoi(port); convErr != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid endpoint %q: port must be an integer between 1 and 65535", endpoint)
	}
	return nil
}

// truncateKeyForDisplay shortens key for a human-facing log line — never
// used for anything security-relevant, just keeps the replacement notice
// readable.
func truncateKeyForDisplay(key string) string {
	const n = 12
	if len(key) <= n {
		return key
	}
	return key[:n]
}

// Pubkey ensures instance's config at path has a keypair —
// self-provisioning one via wireguard.EnsureKeys if it doesn't yet,
// exactly as server/client's first run does — and returns its public
// key. Operational messages go to stderr, never stdout: pair pubkey's
// stdout is a scripting primitive (see cmd/wganchor's runPairPubkeyCmd),
// so it must carry nothing but the key itself.
func Pubkey(cfg *config.Config, path string) (string, error) {
	pub, generated, err := wireguard.EnsureKeys(cfg, path)
	if err != nil {
		return "", err
	}
	if generated {
		fmt.Fprintf(os.Stderr, "generated a new keypair; public key: %s\n", pub)
	}
	return pub, nil
}

// Peer validates and records publicKey (and endpoint, if non-empty)
// as instance's peer identity, persisting only if something actually
// changed — a repeat call with identical arguments is a no-op write, so
// pair run can be re-run freely. Prints a notice to notices (os.Stderr in
// production; a buffer in tests, see pair_test.go) before replacing a
// different, non-empty existing PeerPublicKey: that's the one write in
// this feature with real security weight (it changes who's authorized),
// and silently swapping it is exactly the "stale key from a previous
// attempt" mistake this command exists to make visible instead of easy.
// Also warns (never rejects — see looksLikePrivateKey) if publicKey looks
// like it might actually be a private key.
func Peer(cfg *config.Config, path string, publicKey string, endpoint string, notices io.Writer) error {
	if err := validatePublicKeyFormat(publicKey); err != nil {
		return err
	}
	if endpoint != "" {
		if err := validateEndpoint(endpoint); err != nil {
			return err
		}
	}
	if looksLikePrivateKey(publicKey) {
		_, _ = fmt.Fprintf(notices, "warning: %s... looks like it might be a WireGuard *private* key, not a public one — double check you copied the right value\n",
			truncateKeyForDisplay(publicKey))
	}

	changed := false
	if cfg.PeerPublicKey != publicKey {
		if cfg.PeerPublicKey != "" {
			_, _ = fmt.Fprintf(notices, "replacing existing peer %s... with %s...\n",
				truncateKeyForDisplay(cfg.PeerPublicKey), truncateKeyForDisplay(publicKey))
		}
		cfg.PeerPublicKey = publicKey
		changed = true
	}
	if endpoint != "" && cfg.PeerEndpoint != endpoint {
		cfg.PeerEndpoint = endpoint
		changed = true
	}
	if !changed {
		return nil
	}
	return config.Persist(cfg, path)
}

// parseRemoteExecTemplate splits template on whitespace and substitutes
// its single required "{}" placeholder with target, returning the
// resulting argv prefix. Fails fast (before any subprocess is spawned)
// if the placeholder is missing, duplicated, or template is empty —
// silently dropping the target, or substituting into an ambiguous
// second location, is not an acceptable failure mode for a command that
// writes cryptographic peer identity on a remote host.
func parseRemoteExecTemplate(template, target string) ([]string, error) {
	fields := strings.Fields(template)
	if len(fields) == 0 {
		return nil, fmt.Errorf("--remote-exec is empty")
	}
	placeholders := 0
	idx := -1
	for i, f := range fields {
		if f == "{}" {
			placeholders++
			idx = i
		}
	}
	switch placeholders {
	case 0:
		return nil, fmt.Errorf("--remote-exec %q must contain exactly one {} placeholder (as its own whitespace-separated token) for the remote target", template)
	case 1:
		// fall through
	default:
		return nil, fmt.Errorf("--remote-exec %q must contain exactly one {} placeholder (as its own whitespace-separated token), found %d", template, placeholders)
	}

	argv := make([]string, len(fields))
	copy(argv, fields)
	argv[idx] = target
	return argv, nil
}

// runRemote executes prefix (the resolved --remote-exec argv, target
// already substituted) followed by remoteArgs (the remote wganchor
// invocation), capturing stdout (the only channel pair run ever parses)
// while passing stdin/stderr straight through to the operator's own
// terminal. This deliberately does not reuse internal/sysexec's
// buffer-both-streams contract: sysexec.RunCmd is right for a local,
// non-interactive nft/ip call, but ssh (the default remote-exec target)
// may need an interactive tty for host-key confirmation, a password, or
// a passphrase-protected key, and any remote-side error text should
// reach the operator immediately rather than being wrapped and delayed.
func runRemote(prefix []string, remoteArgs ...string) (string, error) {
	argv := make([]string, 0, len(prefix)+len(remoteArgs))
	argv = append(argv, prefix...)
	argv = append(argv, remoteArgs...)

	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // argv comes from the operator's own --remote-exec/--target flags on this root-run interactive CLI — the same trust boundary as typing the command directly, not external/untrusted input
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		if out := strings.TrimSpace(stdout.String()); out != "" {
			return "", fmt.Errorf("%s: %w (captured stdout: %q)", strings.Join(argv, " "), err, out)
		}
		return "", fmt.Errorf("%s: %w", strings.Join(argv, " "), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// deriveEndpoint returns a convenience default for --endpoint when it
// isn't given explicitly: remote's host (stripping any "user@" prefix)
// paired with the standard listen-port formula for remoteInstance, the
// same one cmd/wganchor's run() already uses for a config missing
// listen_port. Not a guarantee: wrong if the remote's listen_port was
// overridden away from the formula, or if remote is an ssh_config Host
// alias rather than a directly-dialable hostname — both documented in
// --help rather than solved here (pair run never inspects the remote's
// actual config beyond its pubkey). net.JoinHostPort (rather than a bare
// fmt.Sprintf) brackets an IPv6 literal host correctly, e.g.
// "2001:db8::1" -> "[2001:db8::1]:60217", so the result stays parseable
// by validateEndpoint's net.SplitHostPort.
func deriveEndpoint(remote string, remoteInstance int) string {
	host := remote
	if i := strings.LastIndex(host, "@"); i != -1 {
		host = host[i+1:]
	}
	return net.JoinHostPort(host, strconv.Itoa(config.DefaultListenPort(remoteInstance)))
}

// isSelfPair reports whether localPub and remotePub are the same key —
// the pure comparison behind Run's self-pairing guard (step 3),
// extracted so it's directly unit-testable without a real remote exec.
func isSelfPair(localPub, remotePub string) bool {
	return localPub == remotePub
}

// RunOptions configures Run. RemoteInstance and Endpoint are the
// only fields with meaningful zero values requiring special handling —
// see cmd/wganchor's runPairRunCmd, which resolves RemoteInstance's
// default before calling Run, and Run itself, which derives
// Endpoint's default.
type RunOptions struct {
	Instance       int
	RemoteInstance int
	Remote         string
	RemoteExec     string
	Endpoint       string
	ConfigPath     string
}

// Run performs a full pairing exchange against a remote wganchor
// instance: fetch each side's public key and write it as the other's
// peer. Every step is itself a Pubkey/Peer call — locally
// in-process, or remotely via runRemote — so pair run never does
// anything a human couldn't already do by hand with pair pubkey/pair
// peer and their own copy of ssh. See plan-pairing.md for the full
// design rationale, especially why the self-pair guard (step 3) must
// run before the remote push (step 4), not after.
//
// Every purely local, statically-checkable argument (the --remote-exec
// template, the resolved --endpoint) is validated up front, before any
// config is loaded or any remote command is run — a malformed value here
// must never leave the two sides paired asymmetrically (one written,
// the other not) or generate a local keypair before failing.
func Run(opts RunOptions) error {
	if err := config.ValidateInstance(opts.Instance); err != nil {
		return fmt.Errorf("--instance: %w", err)
	}
	if err := config.ValidateInstance(opts.RemoteInstance); err != nil {
		return fmt.Errorf("--remote-instance: %w", err)
	}

	prefix, err := parseRemoteExecTemplate(opts.RemoteExec, opts.Remote)
	if err != nil {
		return err
	}

	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = deriveEndpoint(opts.Remote, opts.RemoteInstance)
	}
	if err := validateEndpoint(endpoint); err != nil {
		return fmt.Errorf("resolving local peer_endpoint: %w", err)
	}

	localPath, checked, err := config.ResolvePath(opts.ConfigPath, opts.Instance)
	if err != nil {
		return fmt.Errorf("no config found for instance %d (checked: %s)", opts.Instance, strings.Join(checked, ", "))
	}
	localCfg, err := config.Load(localPath)
	if err != nil {
		return err
	}

	// Echo the resolved plan before anything — local or remote — runs:
	// it's exactly the line that would have made a missing/wrong
	// --remote-instance visible immediately instead of silently landing
	// on the wrong config, and printing it here (rather than right
	// before step 4) means an operator watching the output has a chance
	// to Ctrl-C before even step 2's remote read runs.
	fmt.Fprintf(os.Stderr, "pairing local %s (instance %d) <-> %s (remote instance %d) via %s\n",
		localPath, opts.Instance, opts.Remote, opts.RemoteInstance, strings.Join(prefix, " "))

	// Step 1: local pubkey (in-process — nothing to shell out to for
	// the local side). Validated before it's ever placed into a
	// remote-exec argv in step 4.
	localPub, err := Pubkey(localCfg, localPath)
	if err != nil {
		return fmt.Errorf("local pubkey: %w", err)
	}
	if err := validatePublicKeyFormat(localPub); err != nil {
		return fmt.Errorf("local pubkey failed self-validation (this should never happen): %w", err)
	}

	// Step 2: remote pubkey.
	remotePub, err := runRemote(prefix, "wganchor", "pair", "pubkey", "--instance", strconv.Itoa(opts.RemoteInstance))
	if err != nil {
		return fmt.Errorf("fetching remote pubkey: %w", err)
	}
	if err := validatePublicKeyFormat(remotePub); err != nil {
		return fmt.Errorf("remote pubkey failed validation: %w (raw output: %q — a shell rc file or MOTD printing to stdout is a common cause)", err, remotePub)
	}

	// Step 3: self-pair guard, before anything is written anywhere. If
	// --remote really does point back at this same instance, the
	// "remote" config in step 4 IS the local one — the guard must fire
	// here, not after step 4 has already overwritten it.
	if isSelfPair(localPub, remotePub) {
		return fmt.Errorf("--remote %q (instance %d) appears to point at this same instance — refusing to pair an instance with itself", opts.Remote, opts.RemoteInstance)
	}

	// Step 4: push local identity to remote. This is the step where a
	// key actually crosses a shell boundary (ssh's remote-command
	// reassembly) — localPub was already validated in step 1.
	if _, err := runRemote(prefix, "wganchor", "pair", "peer",
		"--instance", strconv.Itoa(opts.RemoteInstance),
		"--public-key", localPub,
	); err != nil {
		return fmt.Errorf("pushing local identity to remote: %w", err)
	}

	// Step 5: set peer locally. endpoint was already validated above.
	if err := Peer(localCfg, localPath, remotePub, endpoint, os.Stderr); err != nil {
		return fmt.Errorf("setting local peer: %w", err)
	}
	return nil
}
