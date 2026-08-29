package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeRemoteScript writes a POSIX shell script standing in for a real
// remote wganchor over SSH, for exercising PairRun's orchestration logic
// (step ordering, validation-before-write, idempotence) without a real
// remote or network. It's invoked exactly the way runRemote invokes any
// --remote-exec target: `<script> <target> wganchor pair pubkey|peer ...`.
// Every invocation's argv is logged to $PAIR_TEST_LOG; a `pair peer`
// invocation additionally logs the received --public-key to
// $PAIR_TEST_PEER_LOG, standing in for "the remote's peer got written."
// Setting $PAIR_TEST_FAIL_PUBKEY makes a `pair pubkey` invocation fail,
// simulating a broken remote step.
func writeFakeRemoteScript(t *testing.T) (scriptPath, argvLogPath, peerLogPath string) {
	t.Helper()
	dir := t.TempDir()
	scriptPath = filepath.Join(dir, "fake-remote.sh")
	argvLogPath = filepath.Join(dir, "argv.log")
	peerLogPath = filepath.Join(dir, "peer.log")

	const script = `#!/bin/sh
set -e
echo "$*" >>"$PAIR_TEST_LOG"

mode=""
pubkey=""
while [ $# -gt 0 ]; do
	case "$1" in
	pubkey) mode="pubkey" ;;
	peer) mode="peer" ;;
	--public-key)
		shift
		pubkey="$1"
		;;
	esac
	shift
done

if [ "$mode" = "pubkey" ]; then
	if [ -n "$PAIR_TEST_FAIL_PUBKEY" ]; then
		echo "simulated remote pubkey failure" >&2
		exit 1
	fi
	echo "$PAIR_TEST_REMOTE_PUBKEY"
elif [ "$mode" = "peer" ]; then
	echo "$pubkey" >>"$PAIR_TEST_PEER_LOG"
fi
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAIR_TEST_LOG", argvLogPath)
	t.Setenv("PAIR_TEST_PEER_LOG", peerLogPath)
	return scriptPath, argvLogPath, peerLogPath
}

// readLinesIfExists returns path's non-empty lines, or nil if path was
// never created — the fixture script only creates its log files on first
// write, so "never invoked" and "invoked with no output" both read as nil.
func readLinesIfExists(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// requireWG skips the calling test if `wg` isn't available — PairRun's
// local-side steps always self-provision/derive a real keypair via
// EnsureKeys, unlike the pure --remote-exec/--endpoint validation tests.
func requireWG(t *testing.T) {
	t.Helper()
	if _, _, err := GenerateKeypair(); err != nil {
		t.Skipf("wg not available: %v", err)
	}
}

func newLocalConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := &Config{RelayIPs: []string{"203.0.113.1"}}
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPairRunEndToEndHappyPath is the orchestration-level counterpart to
// pair_test.go's unit tests: it exercises actual step ordering and argv
// construction through PairRun itself, rather than through its live-VPS
// validation alone (see docs/sprints/pairing/plan-pairing.md's exit
// criteria 4, 6, and 7, none of which strictly need a real remote).
func TestPairRunEndToEndHappyPath(t *testing.T) {
	requireWG(t)
	scriptPath, argvLogPath, peerLogPath := writeFakeRemoteScript(t)
	t.Setenv("PAIR_TEST_REMOTE_PUBKEY", samplePubKeyB)

	localPath := newLocalConfigFile(t)

	err := PairRun(PairRunOptions{
		Instance:       0,
		RemoteInstance: 5,
		Remote:         "faketarget",
		RemoteExec:     scriptPath + " {}",
		ConfigPath:     localPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	localCfg, err := loadConfig(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if localCfg.PeerPublicKey != samplePubKeyB {
		t.Fatalf("local PeerPublicKey = %q, want %q", localCfg.PeerPublicKey, samplePubKeyB)
	}
	wantEndpoint := "faketarget:60222" // defaultListenPort(5) == 60217+5
	if localCfg.PeerEndpoint != wantEndpoint {
		t.Fatalf("local PeerEndpoint = %q, want %q", localCfg.PeerEndpoint, wantEndpoint)
	}

	localPub, err := PublicKeyFromPrivate(localCfg.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	peerLines := readLinesIfExists(t, peerLogPath)
	if len(peerLines) != 1 || peerLines[0] != localPub {
		t.Fatalf("remote peer log = %v, want exactly [%q] (the local pubkey pushed in step 4)", peerLines, localPub)
	}

	// The remote instance number is what selects which config file gets
	// written on the far side — Instance (0) and RemoteInstance (5) are
	// deliberately different here so an exact-match assertion on the
	// logged argv catches a --instance/--remote-instance mixup (the
	// exact parameter the production incident turned on), which the
	// PeerEndpoint/peer-log assertions above don't independently cover
	// for the pubkey/peer remote calls themselves.
	argvLines := readLinesIfExists(t, argvLogPath)
	wantArgv := []string{
		"faketarget wganchor pair pubkey --instance 5",
		"faketarget wganchor pair peer --instance 5 --public-key " + localPub,
	}
	if len(argvLines) != len(wantArgv) {
		t.Fatalf("remote invocations = %v, want %d lines: %v", argvLines, len(wantArgv), wantArgv)
	}
	for i := range wantArgv {
		if argvLines[i] != wantArgv[i] {
			t.Errorf("remote invocation %d:\n got  %q\n want %q", i, argvLines[i], wantArgv[i])
		}
	}
}

// TestPairRunSelfPairGuardFiresBeforePush is the orchestration-level
// regression test for the guard-ordering bug caught during plan review:
// the guard must fire before step 4's remote push, not after.
func TestPairRunSelfPairGuardFiresBeforePush(t *testing.T) {
	requireWG(t)
	scriptPath, _, peerLogPath := writeFakeRemoteScript(t)

	localPath := newLocalConfigFile(t)
	localCfg, err := loadConfig(localPath)
	if err != nil {
		t.Fatal(err)
	}
	localPub, _, err := EnsureKeys(localCfg, localPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAIR_TEST_REMOTE_PUBKEY", localPub)

	err = PairRun(PairRunOptions{
		Instance:       0,
		RemoteInstance: 3,
		Remote:         "faketarget",
		RemoteExec:     scriptPath + " {}",
		ConfigPath:     localPath,
	})
	if err == nil {
		t.Fatal("expected a self-pair error")
	}
	if !strings.Contains(err.Error(), "same instance") {
		t.Fatalf("error = %v, want it to mention pairing an instance with itself", err)
	}
	if lines := readLinesIfExists(t, peerLogPath); len(lines) != 0 {
		t.Fatalf("expected step 4 (remote peer push) never to run in a self-pair, but peer log = %v", lines)
	}
}

// TestPairRunInvalidEndpointNeverTouchesRemote is the orchestration-level
// regression test for review finding B2: a malformed --endpoint must fail
// before step 4's remote write, not after it, or the two sides end up
// paired asymmetrically.
func TestPairRunInvalidEndpointNeverTouchesRemote(t *testing.T) {
	requireWG(t)
	scriptPath, _, peerLogPath := writeFakeRemoteScript(t)
	t.Setenv("PAIR_TEST_REMOTE_PUBKEY", samplePubKeyB)

	localPath := newLocalConfigFile(t)

	err := PairRun(PairRunOptions{
		Instance:       0,
		RemoteInstance: 5,
		Remote:         "faketarget",
		RemoteExec:     scriptPath + " {}",
		Endpoint:       "totally-bogus",
		ConfigPath:     localPath,
	})
	if err == nil {
		t.Fatal("expected an error for an invalid --endpoint")
	}
	if lines := readLinesIfExists(t, peerLogPath); len(lines) != 0 {
		t.Fatalf("expected the remote never to be written to when --endpoint is invalid (B2), but peer log = %v", lines)
	}
	localCfg, err := loadConfig(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if localCfg.PeerPublicKey != "" {
		t.Fatalf("local PeerPublicKey should remain unset after a rejected --endpoint, got %q", localCfg.PeerPublicKey)
	}
}

// TestPairRunInvalidRemoteExecTemplateNeverTouchesLocalConfig is the
// orchestration-level regression test for review finding B1: an invalid
// --remote-exec template must fail before step 1 ever runs, so it never
// self-provisions (and persists) a local keypair.
func TestPairRunInvalidRemoteExecTemplateNeverTouchesLocalConfig(t *testing.T) {
	localPath := newLocalConfigFile(t)

	err := PairRun(PairRunOptions{
		Instance:       0,
		RemoteInstance: 0,
		Remote:         "faketarget",
		RemoteExec:     "no-placeholder-here",
		ConfigPath:     localPath,
	})
	if err == nil {
		t.Fatal("expected an error for a --remote-exec template missing {}")
	}
	localCfg, err := loadConfig(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if localCfg.PrivateKey != "" {
		t.Fatalf("expected no local keypair generated before the --remote-exec template is validated (B1), but PrivateKey = %q", localCfg.PrivateKey)
	}
}

// TestPairRunFailedRemotePubkeyLeavesLocalConfigUntouched covers the
// plan's exit criterion that a failed remote step leaves the local config
// completely untouched. The local keypair is pre-provisioned so step 1 is
// a pure read, isolating the assertion to what the failed remote step
// itself changes (see PairRun's doc comment on the one benign,
// documented exception: step 2 self-provisioning a *remote* keypair,
// which this fixture doesn't model since it isn't a real wganchor).
func TestPairRunFailedRemotePubkeyLeavesLocalConfigUntouched(t *testing.T) {
	requireWG(t)
	scriptPath, _, peerLogPath := writeFakeRemoteScript(t)
	t.Setenv("PAIR_TEST_FAIL_PUBKEY", "1")

	localPath := newLocalConfigFile(t)
	localCfg, err := loadConfig(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnsureKeys(localCfg, localPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}

	err = PairRun(PairRunOptions{
		Instance:       0,
		RemoteInstance: 5,
		Remote:         "faketarget",
		RemoteExec:     scriptPath + " {}",
		ConfigPath:     localPath,
	})
	if err == nil {
		t.Fatal("expected an error from the simulated remote pubkey failure")
	}
	if !strings.Contains(err.Error(), "fetching remote pubkey") {
		t.Fatalf("error = %v, want it to mention the remote pubkey step (the fake script's own stderr is passed through live, not captured in the error — by design, see runRemote)", err)
	}
	after, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected local config untouched after a failed remote pubkey step, but it changed:\nbefore: %s\nafter:  %s", before, after)
	}
	if lines := readLinesIfExists(t, peerLogPath); len(lines) != 0 {
		t.Fatalf("expected step 4 never to run after a failed step 2, but peer log = %v", lines)
	}
}

// TestPairRunSecondRunIsNoOpLocally covers the local half of the plan's
// "re-running pair run a second time is a no-op" exit criterion: the
// fixture's fake remote isn't itself idempotence-aware (it logs every
// invocation unconditionally), so only the local config file's
// idempotence — governed by PairPeer's own no-op-write logic — is
// asserted here; the remote half is covered by pair_test.go's
// TestPairPeerIdempotentNoWriteWhenUnchanged, since the same PairPeer
// code runs on a real remote wganchor.
func TestPairRunSecondRunIsNoOpLocally(t *testing.T) {
	requireWG(t)
	scriptPath, _, _ := writeFakeRemoteScript(t)
	t.Setenv("PAIR_TEST_REMOTE_PUBKEY", samplePubKeyB)

	localPath := newLocalConfigFile(t)
	opts := PairRunOptions{
		Instance:       0,
		RemoteInstance: 5,
		Remote:         "faketarget",
		RemoteExec:     scriptPath + " {}",
		ConfigPath:     localPath,
	}
	if err := PairRun(opts); err != nil {
		t.Fatalf("first run: unexpected error: %v", err)
	}
	before, err := os.Stat(localPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := PairRun(opts); err != nil {
		t.Fatalf("second run: unexpected error: %v", err)
	}
	after, err := os.Stat(localPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("expected a second, identical pair run to leave the local config file untouched, but its mtime changed")
	}
}
