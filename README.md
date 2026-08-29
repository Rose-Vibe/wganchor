# wganchor

Expose a VPS's public IP as a locally-bindable network interface on a home
(or any NAT'd) machine, tunneled over WireGuard. Apps on the home machine
bind the VPS's public IP directly; `wganchor` handles the tunnel, the
routing, and (on the client) a default-deny firewall for that IP.

Ships as a single static Linux binary. The same binary plays both roles —
`wganchor server` runs on the VPS, `wganchor client` runs on the home
machine — plus lifecycle (`install`/`uninstall`), self-healing (`watch`),
firewall (`firewall`), and key-exchange (`pair`) subcommands.

## How it works, briefly

A cloud provider's secondary IP can be routed to an instance at the network
layer without ever being bound to a local interface on that instance —
confirmed empirically for Vultr, see `docs/arch/overview.md`. `wganchor`
exploits exactly that: the VPS leaves the secondary IP unbound and routes it
into a WireGuard interface (`wganchor0`); the home machine binds that same
IP on its own `wganchor0` and policy-routes traffic sourced from it back
through the tunnel. No "don't deliver locally" trickery, no dummy
interfaces — just a route on each end and a `/32` address on the client.

See `docs/arch/` for the full design (packet path, config schema, systemd
lifecycle, firewall, self-healing, and key exchange each have their own
doc).

## Requirements

- Linux with **systemd** (only supported init system — `install`/
  `uninstall`/`watch` all shell out to `systemctl`).
- **`wireguard-tools`** (`wg`) and **`iproute2`** (`ip`) on both machines.
- **`nftables`** (`nft`) on the **client** machine only — used for the
  default-deny firewall on the relay interface (skip with `--no-firewall`
  if truly unavailable, though this is a security trade-off, not a
  recommended path).
- **root** — network interface/route/firewall manipulation and systemd
  unit management all require it. There's no capability-scoped mode yet.
- **`ssh`** (client-side only, optional) — only needed if you want the
  automated `wganchor pair run` key exchange. Manual pairing needs nothing
  beyond what's already listed.
- **Go 1.27+** to build from source.

## Build

```
go build -o wganchor .
```

Copy the resulting `wganchor` binary to both the VPS and the home machine
(or build separately on each — it's a single static binary either way).

### Linting

CI runs [`golangci-lint`](https://golangci-lint.run/) (config:
`.golangci.yml`). To run it locally before pushing:

```
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
golangci-lint run    # lint
golangci-lint fmt    # apply gofmt + gofumpt formatting
```

## Command reference

Every subcommand accepts `--instance N` (default `0`) to target a specific
tunnel — see [Multiple tunnels](#multiple-tunnels---instance-n). Run any
subcommand with `-h`/`--help` for the full flag list; `pair run --help` in
particular documents several caveats not repeated here.

**Bring-up** — usually run via systemd (see Lifecycle below), not by hand:
- `wganchor server [--instance N] [--config PATH] [--no-firewall]` — bring
  up the VPS side: interface, keys, peer, routes.
- `wganchor client [--instance N] [--config PATH] [--no-firewall]` — bring
  up the home-machine side: interface, keys, peer, routes, and (unless
  disabled) the default-deny firewall.

**Lifecycle:**
- `wganchor install <server|client> [--instance N] [--no-watch]` — install
  the binary to `/usr/local/bin`, write a config skeleton, enable the
  systemd bring-up unit and (by default) the `watch` companion unit.
- `wganchor uninstall <server|client> [--instance N] [--purge]` — stop and
  disable the units; `--purge` also deletes the config, keys, and the
  interface.

**Firewall** (client-side default-deny — this is how you expose a service):
- `wganchor firewall allow --instance N --port <port|start-end>/<tcp|udp|both>` —
  open a port, a port range, or both protocols for a service you're
  running, e.g. `wganchor firewall allow --instance 0 --port 8080/tcp`, or
  `--port 8000-8010/tcp` for a range, or `--port 53/both` for both
  protocols on one port.
- `wganchor firewall deny --instance N --port <port|start-end>/<tcp|udp|both>` —
  close it again (same spec shapes as `allow`).
- `wganchor firewall enable --instance N` — idempotently (re-)ensure the
  default-deny scaffold exists and the recorded allow-list is applied.
- `wganchor firewall disable --instance N` — fully open, durably (persists
  across reboots — this is the actual "turn it off" command, not
  `--no-firewall`).

**Relay IPs** — the secondary IP(s) being relayed:
- `wganchor relay add <server|client> --instance N --ip <ipv4>` — add a
  relay IP; live-applies immediately if the instance's interface is
  already up, otherwise takes effect on the next bring-up.
- `wganchor relay remove <server|client> --instance N --ip <ipv4>` —
  remove one.

**Pairing** (key exchange between the two sides):
- `wganchor pair run --instance N --remote TARGET [flags]` — automated:
  exchanges public keys with a remote host over SSH.
- `wganchor pair pubkey --instance N` — print this instance's public key
  (self-provisioning a keypair first if it doesn't have one).
- `wganchor pair peer --instance N --public-key KEY [--endpoint HOST:PORT]` —
  record the other side's public key (and endpoint, client only) by hand.

**Self-healing:**
- `wganchor watch <server|client> [--instance N] [--config PATH] [--interval DURATION]` —
  the reconciliation loop; `install` already enables this by default as a
  systemd companion unit, so running it standalone is rarely needed.

## Setup guide

This walks through pairing one VPS with one home machine, instance `0` (the
default — omit `--instance` entirely unless you're running more than one
tunnel, see [Multiple tunnels](#multiple-tunnels---instance-n) below).

### 1. VPS-side prerequisites (not managed by wganchor)

`wganchor` deliberately does not manage the VPS's own firewall or kernel
forwarding — that stays the operator's responsibility, and `install server`
prints a reminder of exactly what's needed:

- A secondary IP assigned to the VPS by your provider, **not** added to
  Netplan/systemd-networkd or bound to any local interface — leave it
  entirely unbound on the VPS.
- `net.ipv4.ip_forward=1`, persisted (e.g. in `/etc/sysctl.d/`).
- Inbound UDP allowed for the WireGuard listen port (`60217` by default for
  instance `0` — see [Notes and gotchas](#notes-and-gotchas)), and
  forwarding allowed both directions between the VPS's public interface and
  `wganchor0`. On a `ufw` host this is `ufw allow 60217/udp` plus
  `ufw route allow` in both directions between the public interface and
  `wganchor0`.

### 2. Install on both machines

```
sudo ./wganchor install server --instance 0     # on the VPS
sudo ./wganchor install client --instance 0     # on the home machine
```

Each `install`:
- Copies the binary to `/usr/local/bin/wganchor`.
- Writes a config skeleton to `/etc/wganchor/0.json` (concrete
  `listen_port`/`interface_name` filled in; `peer_public_key`/
  `peer_endpoint`/`relay_ips` left blank for you).
- Self-provisions a keypair and prints the public key.
- Installs and enables the systemd unit (`wganchor-server@0.service` /
  `wganchor-client@0.service`) **and** a reconciliation-watch companion
  unit (on by default — pass `--no-watch` to skip it, see
  [Self-healing](#self-healing-watch)).
- Attempts to start the service — this **will fail** at this point (no
  peer configured yet) and that's expected; `install` still reports
  success for what it's actually responsible for, and prints a `note:`
  pointing at what to fill in.

### 3. Pair the two sides

Pairing means getting each side's public key (and the VPS's dialable
address) into the *other* side's config. Do this **either** automatically
**or** manually — not both.

#### Automatic (recommended)

From the **client** machine, with SSH access to the VPS:

```
sudo ./wganchor pair run --instance 0 --remote root@<vps-primary-ip>
```

This fetches each side's public key (running `wganchor pair pubkey`/
`wganchor pair peer` on the remote over SSH) and writes each into the
other's config — no manual copy-pasting. A few things worth knowing:

- It's *partially* automatic on purpose: `pair run` only ever touches
  config file fields (`peer_public_key`, `peer_endpoint`). It never brings
  the interface up or restarts anything — you still do that yourself
  (step 5).
- It never sets `relay_ips` on either side — that's still a manual edit
  (step 4).
- The default remote command is `ssh {}`; override with `--remote-exec` for
  a custom port/user/bastion, e.g. `--remote-exec "ssh -p 2222 -l admin {}"`,
  or `--remote-exec "ssh {} sudo"` if you SSH in as a non-root user with
  passwordless (`NOPASSWD`) sudo — see
  [Notes and gotchas](#notes-and-gotchas) for why a password-prompting
  sudo won't work here.
- `wganchor pair run --help` documents every flag and caveat in full,
  including how `--endpoint` is derived when omitted.

#### Manual

Equivalent to the above, run by hand. On the VPS:

```
sudo ./wganchor pair pubkey --instance 0
```

prints the VPS's public key (self-provisioning one first if it doesn't
have one yet — same as `install` already did). Copy it, then on the
**client**:

```
sudo ./wganchor pair peer --instance 0 \
  --public-key <vps-public-key> \
  --endpoint <vps-primary-ip>:60217
```

Then the same in reverse — on the client:

```
sudo ./wganchor pair pubkey --instance 0
```

copy that key, then on the **VPS** (no `--endpoint` needed — only the
client dials out):

```
sudo ./wganchor pair peer --instance 0 --public-key <client-public-key>
```

`pair pubkey`/`pair peer` are the same scriptable primitives `pair run`
calls under the hood — useful if you want to wire up your own automation,
or just don't want to grant SSH access for this.

### 4. Set `relay_ips`

Neither pairing method touches `relay_ips`. On **both** machines, add the
secondary IP(s) being relayed:

```
sudo wganchor relay add server --instance 0 --ip 203.0.113.50   # on the VPS
sudo wganchor relay add client --instance 0 --ip 203.0.113.50   # on the home machine
```

`relay add`/`relay remove` are the recommended way to manage `relay_ips` —
each updates the config and, if the instance's interface is already up,
live-applies the change immediately (no restart needed for a later add/
remove). On this very first setup the interface isn't up yet, so you'll see
a note that the change is recorded and will take effect once you start the
service (step 5).

The manual fallback — editing `/etc/wganchor/0.json` directly — still works
too:

```json
"relay_ips": ["203.0.113.50"]
```

(Config files are mode `0600` and contain a private key — edit as root,
e.g. `sudo nano /etc/wganchor/0.json`.)

### 5. Start (or restart) both sides

```
sudo systemctl restart wganchor-server@0.service   # on the VPS
sudo systemctl restart wganchor-client@0.service   # on the home machine
```

### 6. Verify

```
sudo wg show wganchor0
```

on both machines — look for a recent handshake. Then confirm the relay
actually works: bind a test service to `0.0.0.0` on the home machine and
curl it from *outside* your home network via the relay IP (curling from
the VPS itself is a good stand-in). Remember the client's firewall is
default-deny — see the next section before you do this.

## Firewall (client-side default-deny)

The first time `client` brings up a new `wganchor<N>` interface, it
automatically applies a default-deny nftables firewall scoped to just that
interface (everything else on the machine — LAN, Tailscale, Docker, SSH —
is untouched). Nothing is reachable on the relay IP until you explicitly
allow it:

```
sudo wganchor firewall allow --instance 0 --port 8080/tcp
sudo wganchor firewall deny  --instance 0 --port 8080/tcp
sudo wganchor firewall allow --instance 0 --port 53/both          # both tcp and udp on the same port
sudo wganchor firewall allow --instance 0 --port 8000-8010/tcp    # a whole port range in one call
sudo wganchor firewall allow --instance 0 --port 8000-8010/both   # a range, both protocols
sudo wganchor firewall disable --instance 0   # fully open, persists across reboots
sudo wganchor firewall enable  --instance 0   # re-enable default-deny
```

`/both` is a convenience for services that need both protocols on the same
port (DNS/53, HTTP3-QUIC/443, many game servers) — it's exactly equivalent
to running `allow`/`deny` once for `/tcp` and once for `/udp`; there is no
bare-port default (an unqualified `--port 8080` is rejected) since silently
opening two protocols on a typo'd single-protocol intent is a worse failure
mode than requiring the explicit word. A range (`<start>-<end>/<proto>`) is
allowed or denied as a whole, exact-match only — denying a sub-range of a
previously-allowed wider range is a no-op, not a partial split.

Allowed ports (and an explicit `disable`) are recorded in the config and
re-applied on every bring-up, so they survive a reboot even though the
interface itself is destroyed and recreated. `--no-firewall` on `server`/
`client` skips *applying* firewall state for that one invocation only — it
does not remove rules already in place. This firewall never applies to the
**server** role at all (the VPS doesn't locally bind relay IPs, so there's
nothing to filter there) — the VPS's own inbound firewall is still your
responsibility (step 1).

## Self-healing (`watch`)

`install` also enables `wganchor-watch-<role>@<N>.service` by default
(`--no-watch` to opt out). It watches for external interference — notably,
something on some machines (observed: `systemd-networkd`) periodically
flushing `ip rule` state — and repairs it, both on the actual event and on
a periodic backstop. It only logs when it actually repairs something:

```
journalctl -u wganchor-watch-client@0.service
```

## Multiple tunnels (`--instance N`)

Every subcommand takes `--instance N` (default `0`) for running multiple,
*independent* tunnel relationships side by side — a second, unrelated VPS
with its own keypair, own interface (`wganchor1`), own config
(`/etc/wganchor/1.json`), own listen port (`60218`), own systemd units. (A
*second relay IP through the same tunnel* doesn't need a second instance —
just `wganchor relay add <server|client> --instance N --ip <ip>` on both
sides.) Repeat the setup guide above with `--instance 1`, `2`, etc.

## Uninstalling

```
sudo wganchor uninstall <server|client> --instance 0            # stop/disable, keep config+keys
sudo wganchor uninstall <server|client> --instance 0 --purge    # also delete config, keys, and the interface
```

## Notes and gotchas

- **Root and systemd only.** No capability-scoped execution mode and no
  non-systemd init support yet.
- **Config files must be exactly mode `0600`.** The tool refuses to load
  one that isn't (private keys live inline in the JSON) — if you hand-edit
  with an editor that rewrites permissions, `chmod 600` it back.
- **`relay_ips` is IPv4-only.** An IPv6 entry is rejected at config
  validation.
- **Non-standard defaults are deliberate.** Interface name `wganchor<N>`
  (not `wg0`) and listen port `60217+N` (not `51820`) are chosen
  specifically so `wganchor` never collides with an unrelated,
  conventionally-configured WireGuard setup on the same box.
- **The VPS's own firewall/forwarding/`ip_forward` are never managed by
  wganchor** — see step 1. `install server` reprints this reminder every
  time.
- **Rotating a peer's key doesn't revoke the old one.** `wganchor` only
  ever *adds* a peer to the live WireGuard interface; nothing prunes a
  superseded key. If you re-pair with a new key, the old peer stays
  authorized and handshake-capable until the interface is recreated
  (`uninstall --purge` then reinstall, or manually
  `wg set <iface> peer <old-key> remove`). See `docs/arch/wireguard.md`.
- **`pair run --remote-exec "ssh {} sudo"` needs passwordless
  (`NOPASSWD`) sudo on the remote.** A password-prompting sudo fails
  outright (no tty); forcing a tty (`ssh -t`) trades that for a worse
  failure — the password prompt corrupts the pubkey `pair run` is trying
  to capture. Use a root SSH login, or configure `NOPASSWD` for the
  specific command, instead.
- **`pair run` never brings the interface up.** After pairing, restart the
  service on whichever side(s) changed (step 5) — pairing alone doesn't
  apply anything live.
- **`relay remove` will let you empty out `relay_ips` entirely.** It's not
  refused at the `remove` step — but a subsequent bring-up (`server`/
  `client`) then fails fast with "relay_ips is empty," which is the
  intended place for that check to live.
- **`--remote-instance` is required (not inferred) when `--config` is also
  passed to `pair run`.** Without `--config`, it's inferred from
  `--instance`; that's a footgun once `--config` decouples the local
  instance number from anything meaningful on the remote side — see
  `docs/sprints/archive/2026-08-29-pairing/plan-pairing-COMPLETE.md` for
  why.
- **Something on some machines periodically flushes `ip rule` state**,
  silently breaking new inbound-initiated connections while an existing
  WireGuard handshake keeps looking healthy. The `watch` companion
  (installed by default) detects and repairs this — see
  [Self-healing](#self-healing-watch). If you disabled it with
  `--no-watch`, this class of drift will not self-repair.

## Further reading

- `docs/arch/overview.md` — network design, confirmed provider behavior,
  packet path.
- `docs/arch/wireguard.md` — interface/key management, config schema,
  multi-instance formula, key exchange.
- `docs/arch/config-and-lifecycle.md` — config file format/lookup,
  install/uninstall, systemd units.
- `docs/arch/firewall.md` — the client-side default-deny firewall design.
- `docs/arch/resilience.md` — the `watch` self-healing design.
- `docs/sprints/archive/` — completed feature plans, including full design
  rationale for `pair` (automated key exchange).

## License

MIT — see [`LICENSE`](LICENSE).
