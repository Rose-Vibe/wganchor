# Sprint: Bootstrap

## Purpose

This is the first sprint. There is no code and no architecture doc yet, so
this sprint's job is to turn assumptions into a validated design and a
working environment, before any Go is written. Concretely:

1. Research the pieces we don't yet have confirmed answers for, and write
   them down in `docs/arch/`.
2. Get both machines (VPS, home) into a state where WireGuard and Go are
   ready to use.
3. Prove the core mechanism — a provider-assigned secondary IP on the VPS,
   relayed to the home machine over WireGuard so a local process can bind
   it directly — works at all, by hand, before automating it.
4. Stand up the Go project skeleton (`server`/`client` subcommands, config
   loading) that later sprints will fill in.

Only once the manual PoC in `plan-wireguard-poc.md` succeeds does it make
sense to plan a sprint that replaces the manual steps with the real Go
implementation — that's sprint 2, not this one.

## Checkpoint: pause after research, before environment/PoC execution

Once `plan-research.md`'s exit criteria are all checked off and the
research plan-reviewer has approved, **stop and summarize the finished
research (and the resulting `plan-environment.md` /
`plan-wireguard-poc.md`, updated to reflect what research found) for the
user, then wait for their explicit go-ahead** before running any step in
`plan-environment.md` or `plan-wireguard-poc.md`. Everything up to and
including research/planning is autonomous per CLAUDE.md's normal pipeline;
this checkpoint is a deliberate exception the user asked for, specific to
this sprint, because the following steps start making real changes
(installing packages, editing sysctl, generating keys, bringing up a
tunnel) and the user wants to read the plan first.

Once the user gives the go-ahead past this checkpoint, resume the normal
autonomous pipeline (no further per-step check-ins) through the rest of
`plan-environment.md` and `plan-wireguard-poc.md`, stopping only per the
standard CLAUDE.md exceptions (architectural conflict, irreversible
consequence, systemic test failure, unsafe/destructive action).

- [ ] User go-ahead received past this checkpoint (date): ____

Check this box and fill in the date the moment the user gives the
go-ahead — a fresh agent picking this sprint up later (after compaction,
or a new session) has no other way to tell whether the checkpoint has
already been passed, and would otherwise either stall re-asking or guess
from unrelated checked boxes.

## Known environment (as of sprint start, 2026-08-28)

This section is a snapshot from when the sprint began — it is **not**
kept in sync with progress; check `plan-research.md` / `plan-environment.md`
for current state (e.g. the secondary IP mentioned as unassigned below has
since been assigned — see `plan-environment.md`).

- VPS: Vultr instance, Ubuntu 26.04 LTS, kernel 7.0.0 (in-kernel WireGuard
  support, no DKMS needed). Single public IPv4 at sprint start
  (`ip -brief addr` on `enp1s0`); no secondary IP assigned yet at that
  point.
- Home machine: Ubuntu 24.04 LTS, kernel 6.8.0 (in-kernel WireGuard
  support).
- Neither machine had `wireguard-tools` or a Go toolchain installed at
  sprint start.
- SSH access to the VPS is via key (`~/.ssh/id_ed25519`), password kept as
  fallback in `.env`. See `scripts/setup-env.sh`.

## Plans

- `plan-research.md` — fill the open design questions, write `docs/arch/`.
- `plan-environment.md` — provision the secondary IP, install prerequisites
  on both machines.
- `plan-wireguard-poc.md` — manual (non-Go) proof that the relay mechanism
  works end-to-end, plus the Go project skeleton.

## Exit criteria for the sprint

- `docs/arch/` describes the network design, the WireGuard key/config
  model, and the Go libraries we'll build on, with enough detail that
  sprint 2 can be planned from it alone.
- Both machines have `wireguard-tools` installed; the VPS has a working
  secondary public IP.
- An external host can reach a test listener bound to the secondary IP on
  the *home* machine, through a manually-configured WireGuard tunnel.
- `wganchor` builds as a single static binary with `server` and `client`
  subcommands that parse a config file and no-op otherwise.
