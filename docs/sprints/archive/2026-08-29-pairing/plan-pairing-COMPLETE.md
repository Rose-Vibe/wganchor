# Plan: `wganchor pair` — automating the manual key exchange

Depends on `docs/arch/wireguard.md`'s "Keys and key exchange" section,
which explicitly left this door open: *"A dedicated `keygen`/`init`
subcommand can be added later if key rotation or pre-provisioning needs
it; not required for v1."* This plan is that subcommand, scoped to
exchange specifically (not rotation — see Non-goals).

## Motivation

Today, pairing two wganchor instances means: start each side, find its
printed public key in the terminal output, and manually paste it into
the *other* side's config file. That's fine for a single one-off setup
but is easy to fumble (wrong instance, wrong field, stale key from a
previous attempt) and doesn't scale if someone sets up several instances.

Raised in conversation with the user (not a live incident): does it make
sense to automate this over SSH? Decided: yes, with two conditions the
user was explicit about:

1. **Nothing about the trust model changes.** WireGuard's own pubkey
   pairing remains the entire authorization mechanism (see
   `docs/arch/firewall.md`'s and this session's own explanation of that
   model). This plan automates *populating the same config fields* a
   human would otherwise copy-paste — it does not introduce a new
   identity, account, or credential system, and does not touch
   `ValidateConfig`'s or `ConfigureInterface`'s notion of what makes a
   peer authorized.
2. **SSH is an optional convenience, not a new hard dependency**, and
   this isn't actually a new *kind* of dependency: `wganchor` already
   shells out to `wg`, `ip`, `nft`, and `systemctl`. `ssh` (or whatever
   the operator points `--remote-exec` at) joins that same list — used
   only by the new `pair run` orchestrator, never by `server`/`client`/
   `watch`/`firewall`, all of which remain exactly as SSH-free as today.

## Goal

Add a `wganchor pair` subcommand family:

- `wganchor pair pubkey --instance N` — print this instance's public
  key, non-interactively, self-provisioning a keypair first if none
  exists yet (same self-provisioning `EnsureKeys` already does on
  `server`/`client`'s first run).
- `wganchor pair peer --instance N --public-key KEY [--endpoint HOST:PORT]`
  — write the given public key (and, optionally, endpoint) into this
  instance's own config as its peer's identity, non-interactively.
- `wganchor pair run --instance N --remote TARGET [flags]` — the
  orchestrator: runs `pair pubkey`/`pair peer` locally, and the same two
  commands *on the remote side* via a pluggable remote-execution
  mechanism (default: SSH), so a full exchange happens in one invocation.

Every step `pair run` performs is *itself* a `pair pubkey`/`pair peer`
invocation — the exact same command a human could type by hand (locally,
or after `ssh`-ing in themselves). `pair run` doesn't do anything a human
couldn't already do with `pair pubkey`/`pair peer` plus their own copy of
SSH; it just automates the copying.

**v1 is scoped to running `pair run` from the client side, against the
server** (see the `--push-endpoint` decision under Non-goals): this is
already the natural direction, since the client is the side that needs
`peer_endpoint` (`ValidateConfig` requires it only for `role ==
"client"`) and is usually the side an operator is sitting at. Running it
the other way round still exchanges pubkeys correctly, but leaves the
client's `peer_endpoint` for the operator to set by hand (or a
follow-up `pair run` from the client) — that asymmetry is deliberate, not
a bug; see Non-goals.

## Non-goals

- **Key rotation or revocation.** Still out of scope, per
  `docs/arch/wireguard.md`'s original note. `pair pubkey` only ever
  *reads* an existing key or generates one if entirely absent — it never
  regenerates over an existing key. Rotating a compromised key remains a
  manual "clear `private_key`, re-run, re-pair" operation, unchanged from
  today.
- **wganchor managing SSH credentials/known_hosts/agents.** `pair run`
  invokes whatever `--remote-exec` names; it is that command's job (SSH's,
  by default) to authenticate. wganchor never touches SSH config, keys,
  or `known_hosts`.
- **Auto-discovery of the remote instance number, listen port, or
  reachable address.** `--remote-instance` defaults to the local
  `--instance`, and `--endpoint`'s host:port must be given or derived
  from `--remote` + the standard listen-port formula (see "Deriving
  `--endpoint`" below) — `pair run` never inspects the remote's actual
  live `listen_port`/`interface_name` beyond what it explicitly asks for.
- **Pushing `peer_endpoint` to the remote side (`--push-endpoint`).**
  Considered and cut for v1: the derived-endpoint story is already
  shaped around "run from the client," the reversed direction (SSHing
  from a public VPS into a NAT'd home machine) is the rare case, and
  every flag whose value flows into a remote-exec argv is something to
  validate and reason about (see "The `--remote-exec` mechanism" below)
  — one fewer is worth it for
  v1. If server→client pairing becomes a real need, add it later as its
  own flag with the same `host:port` validation `pair peer`'s own
  `--endpoint` gets.
- **Bringing the interface up.** `pair run` only ever touches config
  fields (via `pair peer`) — it never calls `ConfigureInterface`,
  `EnsureInterface`, or restarts anything. `server`/`client` (or `watch`,
  if already running against a config that gets a new peer_public_key —
  see caveat below) still need a subsequent run to apply it live.

## Design

### `wganchor pair pubkey --instance N [--config PATH]`

Reuses `EnsureKeys` exactly as `run()` does today (`main.go:238`), against
the config resolved via `resolveConfigPath` — **the same flexible
lookup `server`/`client`/`watch` already use** (XDG user path first, then
`/etc/wganchor/<N>.json`; config.go:69), not `firewall`'s fixed
`configPathForInstance`. This matters concretely: `pair` writes fields
that `server`/`client` later *read*, so it must resolve to the exact same
file those commands would load — a fixed-path lookup would let an
operator using an XDG user-level config have `pair` silently write into
`/etc/wganchor/0.json` while `client` keeps loading (and using) the XDG
file, landing the new peer identity nowhere that matters. `firewall` can
get away with the fixed path because it's inherently a root/system
operation tied to `nft`; `pair` isn't, so it follows `server`/`client`'s
precedent instead. `--config` is kept as the same explicit override
`server`/`client`/`watch` already support, on the same terms —
`resolveConfigPath` also gives the "must already have a real config"
precondition and the actionable "checked: ..." error message for free.

No explicit root/`Geteuid` check. `pair pubkey`/`pair peer` never call
`nft` or touch the network stack — they run `wg genkey`/`wg pubkey`
(unprivileged) and read/write the config file, exactly like `run()`
itself, which has no euid check either. The config file's own `0600`
root-owned permissions (once installed via `install`) naturally require
root to write it in the production path; an explicit check would only
get in the way of the `--config`-based local-testing story this design
already relies on for non-root test fixtures.

**Output contract**: exactly the public key on stdout, nothing else — no
"generated a new keypair" prose, no trailing newline beyond the one
`fmt.Println` adds. This is a scripting primitive: `pair run` (and any
operator's own script) must be able to capture its stdout directly as
the key with no parsing. Any operational messages (e.g. "generated a new
keypair") go to stderr instead, unlike `run()`'s current stdout-based
messaging — a deliberate, narrow inconsistency with `run()`'s existing
`fmt.Printf` calls, justified by this command's specific
script-composability requirement.

### `wganchor pair peer --instance N --public-key KEY [--endpoint HOST:PORT]`

- Validates `KEY` is a well-formed WireGuard public key (32 raw bytes,
  standard base64 — reuse the same shape `GenerateKeypair`/
  `PublicKeyFromPrivate` produce) before writing anything, with an
  actionable error otherwise. Every key `pair run` ever places into a
  remote-exec argv (see below) is validated *before* that happens, on
  the local side that's constructing the command — this is what actually
  matters for the remote-exec safety property, not the write-side check
  alone (see "The `--remote-exec` mechanism").
- Validates `--endpoint`, if given, as a well-formed `host:port` via
  `net.SplitHostPort` before writing — `ValidateConfig` today only
  checks non-emptiness, so a malformed endpoint would otherwise surface
  later as an opaque `wg set`/dial error instead of failing fast here,
  against `validate.go`'s existing posture.
- If this instance already has a *different*, non-empty
  `PeerPublicKey`, print a notice to stderr before overwriting it (e.g.
  `replacing existing peer <old, truncated>... with <new, truncated>...`)
  — this is the one write in this whole feature with real security
  weight (it changes who's authorized), and it's exactly the Motivation's
  "stale key from a previous attempt" scenario where an operator most
  needs to notice something changed.
- Writes `PeerPublicKey` (and `PeerEndpoint`, if `--endpoint` was given)
  via `persistConfig`, same idempotent-write pattern as `FirewallAllow`
  (`firewall.go:570`) — a no-op write (skip `persistConfig` entirely) if
  the values already match, so re-running `pair run` twice doesn't
  needlessly rewrite the file (and doesn't print the replacement notice
  when nothing actually changed).
- Does **not** validate the full config (`ValidateConfig`) or touch
  `RelayIPs`/`ListenPort`/anything else — it only ever touches these two
  fields, by design (the smallest atomic unit `pair run` needs).
- No explicit root check, for the same reason as `pair pubkey` above.

### `wganchor pair run --instance N --remote TARGET [flags]`

```
wganchor pair run --instance N --remote TARGET
                   [--remote-instance M]        (default: N)
                   [--remote-exec TEMPLATE]      (default: "ssh {}")
                   [--endpoint HOST:PORT]        (sets local PeerEndpoint)
                   [--config PATH]               (local side only — see below)
```

`--config`, if given, applies only to the **local** side's lookup; the
remote invocation always uses the remote `wganchor`'s own default
`resolveConfigPath` lookup (there is no way, and no need, for `pair run`
to tell the remote side where to find its own config — that's the
remote operator's `--config`/XDG/install setup, not this command's
concern).

Sequence:

1. **Local pubkey**: call the same logic `pair pubkey` uses, in-process
   (no subprocess — there's nothing to shell out to for the local side).
   Validate its shape (belt-and-suspenders — it's `wg pubkey`'s own
   output, but see "The `--remote-exec` mechanism" below for why this is
   the copy that actually matters) before it's ever placed into a
   remote-exec argv in step 4.
2. **Remote pubkey**: run `wganchor pair pubkey --instance M` on the
   remote via the resolved remote-exec command (below); capture stdout,
   trimmed, as the remote's public key. Validate its shape immediately
   before using it anywhere, since it just came from an external
   process's output. (This key is only ever consumed by step 5's
   in-process call — it never flows through another shell, but
   validating it early still catches a broken/wrong remote binary fast,
   with a clear error instead of a confusing downstream one.)
3. **Guard against self-pairing, before anything is written anywhere**:
   if the remote pubkey from step 2 equals the local pubkey from step 1,
   fail with an actionable error (`--remote appears to point at this
   same instance`) instead of proceeding to write a self-referential
   peer that WireGuard will never complete a handshake against. This
   must run **before** step 4: if `--remote` really does point back at
   this same instance, step 4's remote `pair peer` push would otherwise
   already have overwritten the instance's own config with itself as its
   peer by the time any guard fired — "leaves the local config
   untouched" is the wrong property to protect here, since in the
   self-pair case the "remote" config *is* the local one. **Scope note**
   (caught in implementation review): this only catches pairing an
   instance with *itself* — it does not catch `--remote-instance`
   pointing at some *other* wrong-but-distinct instance, which is a
   different mistake with different keys on both sides and nothing for a
   pubkey comparison to catch. See "Safeguard: `--remote-instance` with
   `--config`" below for the mistake that guard is actually for.
4. **Push local identity to remote**: run
   `wganchor pair peer --instance M --public-key <local-pubkey>` on the
   remote via remote-exec. **This is the step where a key actually
   crosses a shell boundary** (see below) — the already-validated local
   pubkey from step 1 is what gets interpolated here.
5. **Set peer locally**: call `pair peer`'s logic in-process with
   `--public-key <remote-pubkey>` and `--endpoint <endpoint>` (if
   `--endpoint` was given).

**Validation ordering (caught in implementation review, B1/B2 below):**
the `--remote-exec` template and the resolved `--endpoint` (explicit or
derived) are both purely local, statically-checkable inputs — neither
depends on anything step 1 or step 2 fetch. Both are parsed/validated
*before* step 1 runs, not interleaved between steps as an earlier
implementation had it: a malformed `--remote-exec` must fail before a
local keypair is ever self-provisioned and persisted, and a malformed
`--endpoint` must fail before step 4 has already written the remote
side — leaving the two sides paired asymmetrically is exactly the
"leaves the local config untouched" property extended to also mean
"leaves the remote asymmetrically paired," which step 5 alone can't
guarantee if `--endpoint` is only checked there.

### Safeguard: `--remote-instance` with `--config`

Added after a live-testing incident (not a plan-review finding): running
`pair run` with `--config` pointed at a disposable local test config,
but forgetting `--remote-instance`, silently defaulted the remote
instance number to `--instance`'s value — which, in production, wrote a
disposable test key into a real instance's config on the remote. The
underlying mechanism: `resolveConfigPath` returns early when `--config`
is given, ignoring `instance` entirely for the *local* lookup, so
`--instance`'s number becomes a pure label with no bearing on which
local file gets used — but `--remote-instance`'s default still silently
inherited that now-meaningless number, and unlike the local side, it
*does* select a real file on the remote.

Fix: `runPairRunCmd` now hard-errors if `--config` is given without
`--remote-instance` also given explicitly (detected via `fs.Visit`,
since the flag's zero value can't distinguish "explicitly set to the
default" from "left unset"). Deliberately *not* required unconditionally
— for the ordinary `--instance 0` with no `--config` case, inheriting
`--remote-instance` from `--instance` is correct, and forcing the flag
everywhere would train the operator to type it reflexively, which is
exactly how it eventually gets typed wrong.

**Scope note (caught in implementation re-review)**: `--config` is the
*trigger* for this specific guard, not the actual root cause — the
deeper issue is that a local instance number never carries any
guarantee about remote instance semantics; an operator with a
disposable XDG-located config for local instance 0 sitting alongside a
real instance 0 on the VPS hits the identical mistake with no `--config`
involved at all, and this guard alone wouldn't catch it. The echo line
below is what covers that broader case, since it names the remote
instance number explicitly regardless of how the local config was
resolved.

Two further mitigations added alongside the safeguard:
- `pair run` echoes the resolved local path, instance numbers, and
  resolved remote-exec argv to stderr before anything runs, local or
  remote — cheap, and it's exactly the line that would have made the
  incident visible the moment it happened.
- `pair peer` (and therefore every `pair run` peer write, local or
  remote) now also warns to stderr if the public key it's about to write
  looks like it might actually be a private key (see `looksLikePrivateKey`
  in `pair.go`) — a heuristic based on `wg genkey`'s key-clamping
  structure, not a hard rejection (public keys satisfy it by chance
  ~1/16 of the time), but it catches the single most common manual
  copy-paste mistake this feature exists to prevent.

Steps 2 and 4 are the two separate remote invocations, rather than one
combined "exchange" remote subcommand — keeping `pair pubkey`/`pair
peer` as the only two things that ever run against a config (locally or
remotely) means there is exactly one code path for "read a pubkey" and
one for "write a peer," used identically whether invoked directly by a
human, over SSH by `pair run`, or (hypothetically) by some other
orchestration someone builds later.

**Partial-failure recovery is idempotence, not special-cased rollback.**
If step 2 fails outright, or step 3's guard trips, `pair run` exits
before step 4, so the remote's *peer fields* are never written and the
local config is never touched by *that* invocation — the one benign
exception is step 2's remote `pair pubkey` call itself, which can
self-provision and persist a fresh keypair on the remote if it didn't
have one yet, identical to what a first `server`/`client` run there
would have done anyway. But the picture is one-sided once
step 4 has run: step 4 can succeed on the remote and then step 5's local
`persistConfig` can still fail, leaving the remote paired while the
local side isn't. There is no explicit rollback of the remote step —
every one of `pair pubkey`/`pair peer`'s writes is itself idempotent, so
simply re-running `pair run` after fixing whatever failed converges both
sides correctly. State this in `--help`/docs rather than implying a
transaction that doesn't exist.

**Remote-exec process wiring**: stdout is captured (it's the only
channel `pair run` parses — the pubkey, trimmed); stderr is passed
through live (inherited from `pair run`'s own stderr), not buffered,
so an interactive SSH prompt (host-key confirmation, a password, a
passphrase-protected key) is visible and usable exactly as if the
operator had typed the `ssh` command themselves, and any remote-side
error text (`wganchor: command not found`, `must be run as root`, stale
usage output from an old remote binary lacking `pair`) reaches the
operator immediately rather than being swallowed. This is a deliberate
departure from `runCmd`'s existing stderr-buffering (`exec.go:13`),
which is fine for a local, non-interactive `nft`/`ip` call but wrong
here. If step 2's captured stdout fails shape validation, include the
raw captured output in the error — a shell rc file or MOTD that prints
to stdout is a realistic, known cause of that kind of pollution, and
seeing the actual bytes is the fastest way to diagnose it.

#### Deriving `--endpoint`

If `--endpoint` isn't given but `--remote` looks like `[user@]host` (no
explicit SSH port needed for the WireGuard endpoint), default it to
`<host>:<defaultListenPort(remote-instance)>` — the same formula
`main.go`'s `run()` already uses for a config missing `listen_port`. This
is a convenience default, not a guarantee, for two independent reasons:
if the remote's actual `listen_port` was overridden away from the
formula's value, or if `--remote` is an `ssh_config` `Host` alias rather
than a real, directly-dialable hostname, the derived endpoint is wrong.
Document both plainly in `--help` rather than trying to ask the remote
for its real `listen_port`/resolve its alias (see Non-goals — v1
deliberately doesn't inspect remote config beyond the pubkey).

### The `--remote-exec` mechanism

Default: `"ssh {}"`.

The template is split on whitespace into argv tokens (no shell-quoting
support in v1 — an operator needing a token containing a space should
wrap their own logic in a script and point `--remote-exec` at the
script's path instead, which itself may take further arguments split the
same simple way). The resulting tokens **must contain exactly one
literal `{}` token** — `pair run` substitutes it with `--remote`'s value
verbatim, then appends the remote wganchor invocation's own argv tokens
(subcommand name, `--instance`, the instance number, `--public-key`, the
key, etc. — each already a separate, wganchor-constructed argv element)
at the end. The whole thing is `exec.Command`'d directly, with **no
local shell involved** — `{}` and the appended tokens are passed as
literal argv elements to whatever `--remote-exec`'s first token names, so
there's no local shell-injection surface from either the target string
or wganchor's own generated arguments.

A missing `{}`, or more than one `{}`, in a custom `--remote-exec` is a
hard, actionable error at `pair run` startup (before touching anything)
— silently dropping the target, or substituting into an ambiguous
second location, is not an acceptable failure mode here. Same for an
empty or whitespace-only template.

The **remote** side is a different story, and is the one place a
wganchor-controlled value genuinely crosses a shell boundary: SSH (like
most remote-exec tools) reassembles its trailing arguments into a single
string and hands that to the remote user's shell to parse. Step 3 (`pair
run` pushing the local pubkey to the remote) is exactly that case — the
local pubkey, already validated as strict WireGuard-key-shaped base64
(`A-Za-z0-9+/=`, no shell metacharacters) before this point, is the value
riding through that reassembly. That's why the validation in `pair
peer`'s design above is described as happening "on the local side that's
constructing the command," not merely at the remote write — the
remote's own `pair peer` validating again on arrival is real
defense-in-depth, but the actual defense is validating before the value
is ever placed in argv.

Examples:

- Default: `--remote vps.example.com` → executes
  `ssh vps.example.com wganchor pair pubkey --instance 3`.
- Custom port/user: `--remote-exec "ssh -p 2222 -l admin {}"` →
  `ssh -p 2222 -l admin vps.example.com wganchor pair pubkey --instance 3`.
- Non-root SSH user needing privilege on the remote: `--remote-exec "ssh
  {} sudo"` → `ssh vps.example.com sudo wganchor pair pubkey --instance
  3` — this falls directly out of the "append after `{}`" template
  design. **Caveat found in implementation review**: this only works if
  the remote's `sudo` is configured `NOPASSWD` for the invoking user.
  Without a tty, a password-requiring `sudo` fails outright (no askpass
  program); allocating one (`ssh -t {} sudo`) trades that failure for a
  worse one — with a pty allocated, the remote process's stderr (and any
  password prompt) folds into the same stream `pair run` reads as
  stdout, which would corrupt the captured pubkey. Documented as a
  `NOPASSWD` requirement in `--help` rather than solved further in v1.
- Fully custom tooling: `--remote-exec "my-bastion-wrapper --target {}"` →
  `my-bastion-wrapper --target vps.example.com wganchor pair pubkey --instance 3`.

This mirrors `rsync -e`/`git`'s `GIT_SSH_COMMAND` in spirit (pluggable
remote-shell command, SSH by default) but uses an explicit `{}`
placeholder rather than pure positional appending, since the user
specifically asked for substitution-based override rather than
"wganchor's target is always argv[1]."

## Interaction with existing subcommands

- `install`/`uninstall`/`server`/`client`/`watch`/`firewall` are
  completely unaffected — `pair` only ever writes `PrivateKey`/
  `PeerPublicKey`/`PeerEndpoint` via the same `persistConfig` those
  already use, so there's no new state, only a new way to populate two
  fields that already existed.
- **Caveat to document, not solve here**: if `pair run` changes
  `peer_public_key` on an instance whose `server`/`client` (and
  `watch`) are already running, the live WireGuard interface won't
  reflect the new peer until the next `server`/`client` invocation
  re-runs `ConfigureInterface` (`reconcileOnce`, watch.go:158, only ever
  calls `ReconcileServerRoutes`/`ReconcileClientRouting` — it never
  re-runs `wg set ... peer`). This matches "pair only touches config"
  from the Goal section; call it out in `--help` and in the exit
  criteria below rather than silently restarting anything on the
  operator's behalf.
- A `peer_endpoint` written into a **server**-role config (e.g. if an
  operator did derive/set one there manually) is inert either way:
  `ConfigureInterface` only ever applies `endpoint` for the client role
  (`iface.go:80`). Not a `pair`-specific concern given `--push-endpoint`
  is cut for v1, but worth knowing if that decision is revisited.
- **Known limitation (found in implementation review), not solved in
  v1**: `pair run` loads the local config once at startup and writes it
  back once at step 5, a window that can span a whole interactive SSH
  round-trip (host-key confirmation, a password prompt) lasting minutes.
  A concurrent `wganchor firewall allow/deny` against the same instance
  during that window — which also loads-then-writes the full config —
  would silently clobber whichever of the two wrote last. Narrow in
  practice (both writers are operator-driven, and `watch` never
  persists the config), so not worth solving for v1; noted here rather
  than solved so a future reader doesn't rediscover it as a surprise.

## Exit criteria

- [x] `pair pubkey` prints exactly the public key on stdout (nothing
      else), self-provisions a keypair on first call the same way
      `server`/`client` do, and is idempotent (repeated calls return the
      same key, never regenerate over an existing one). Resolves the
      config via `resolveConfigPath`, matching `server`/`client`/`watch`
      exactly (verified: pointing `pair pubkey` at an XDG-located config
      and then running `client` against the same instance number with no
      `--config` picks up the same file).
- [x] `pair peer` validates key format and `--endpoint` shape before
      writing anything (unit tested against malformed input: wrong key
      length, non-base64 characters, a malformed `host:port`); **and
      warns without rejecting** when the key carries `wg genkey`'s
      clamping structure and so looks like it might actually be a
      private key (format alone can't reject it — see
      `looksLikePrivateKey`) — covered by
      `TestPairPeerWarnsWhenPublicKeyLooksLikePrivateKey` and
      `TestPairPeerNoWarningForOrdinaryPublicKey`. Writes are idempotent
      no-ops when the values already match (verified the config file's
      mtime/content doesn't change on a repeat call with identical
      arguments, and the replacement notice does NOT print on that
      no-op repeat); the replacement notice DOES print (to stderr) when
      overwriting a different, non-empty existing `PeerPublicKey`.
- [x] `pair run`'s `--remote-exec` template parsing is unit-tested: the
      default, a custom template with `{}` in a non-trailing position, a
      custom template missing `{}`, a template with `{}` appearing
      twice, and an empty/whitespace-only template — the last three must
      all fail fast with an actionable error, no subprocess ever
      spawned.
- [x] `pair run` refuses to pair an instance with itself (step 2's
      remote pubkey equal to step 1's local pubkey), unit-tested against
      the pure comparison, against a fake-remote-exec fixture asserting
      the guard fires before step 4's remote write
      (`TestPairRunSelfPairGuardFiresBeforePush`), and live-verified with
      `--remote` accidentally pointed at the same instance.
- [x] `pair run` is live-validated against the actual VPS (SSH access
      already confirmed working this session) end to end, run from the
      client side: run against a disposable instance's client-side
      config, confirm the VPS's corresponding disposable server-side
      config actually got the client's real public key, and the client's
      config got the server's real public key + a working
      `peer_endpoint` — then bring both sides up for real and confirm a
      working tunnel (reusing this session's own external-vantage-point
      reachability pattern, not a loopback check) with **no manual
      copy-paste of any key** anywhere in the process. **Deferred**:
      verifying the `ssh {} sudo` form against a non-root SSH login — no
      such account exists on the test VPS. Documented instead as a
      `NOPASSWD`-only limitation (see "The `--remote-exec` mechanism"
      above), not silently claimed to work.
- [x] A failed remote step (bad `--remote`, remote `wganchor` binary
      missing/old/lacking `pair`, remote pubkey command erroring) leaves
      the local config untouched, with the one documented exception that
      step 1 may self-provision a keypair if the local instance had
      none — verified by diffing the config file before/after a
      deliberately-broken `pair run` invocation against a
      **pre-provisioned** instance
      (`TestPairRunFailedRemotePubkeyLeavesLocalConfigUntouched`), and
      surfaces the remote's actual stderr/stdout to the operator rather
      than an opaque wrapped error (stderr is passed through live by
      design; captured stdout is included in the wrapped error on
      failure).
- [x] Re-running `pair run` a second time against an already-paired pair
      is a no-op on both sides' config files (no unnecessary rewrites,
      no replacement notice), and still exits 0. The local half is
      covered directly (`TestPairRunSecondRunIsNoOpLocally`); the remote
      half runs the identical `PairPeer` code path, covered by
      `TestPairPeerIdempotentNoWriteWhenUnchanged`.
- [x] `docs/arch/wireguard.md`'s "Exchange: manual/file-based... No
      auto-exchange protocol in scope" line is updated once this ships —
      not "wrong" exactly (the underlying exchange is still file-based;
      `pair` only automates *performing* the manual step), but should
      point here so a future reader doesn't take that line as still
      literally true.
