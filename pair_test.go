package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real keys generated via `wg genkey`/`wg pubkey` for this test file —
// their actual cryptographic validity doesn't matter here, only that
// they're genuinely well-formed (standard base64, 32 raw bytes), so
// tests exercise the real shape validatePublicKeyFormat checks against.
const (
	samplePubKeyA = "+BNNJ3yrenqi2hfu4UvceIPg3SgEP9XkgiIMKqJ1r1M="
	samplePubKeyB = "tkATMMUZ2K12cIQhl46gWa8P0lP2YJnucOt1IkfJEDI="
)

func TestValidatePublicKeyFormatValid(t *testing.T) {
	for _, key := range []string{samplePubKeyA, samplePubKeyB} {
		if err := validatePublicKeyFormat(key); err != nil {
			t.Fatalf("validatePublicKeyFormat(%q): unexpected error: %v", key, err)
		}
	}
}

func TestValidatePublicKeyFormatInvalidLength(t *testing.T) {
	// Valid base64, but decodes to fewer than 32 bytes.
	if err := validatePublicKeyFormat("dG9vc2hvcnQ="); err == nil {
		t.Fatal("expected an error for a too-short key")
	}
}

func TestValidatePublicKeyFormatInvalidBase64(t *testing.T) {
	if err := validatePublicKeyFormat("not-valid-base64!!!"); err == nil {
		t.Fatal("expected an error for non-base64 input")
	}
}

func TestValidatePublicKeyFormatEmpty(t *testing.T) {
	if err := validatePublicKeyFormat(""); err == nil {
		t.Fatal("expected an error for an empty key")
	}
}

// TestValidatePublicKeyFormatCannotDistinguishPrivateFromPublic documents
// a real, inherent limitation rather than a bug: validatePublicKeyFormat
// checks shape only (32 raw bytes, standard base64), which a private key
// satisfies exactly as well as a public key does, so a syntactically
// valid private key passed where a public key was expected passes this
// check too. Callers must not rely on validatePublicKeyFormat itself to
// catch that mistake — see looksLikePrivateKey for a separate, imperfect
// heuristic that helps with it instead.
func TestValidatePublicKeyFormatCannotDistinguishPrivateFromPublic(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Skipf("wg not available to generate a real private key: %v", err)
	}
	if err := validatePublicKeyFormat(priv); err != nil {
		t.Fatalf("a private key is format-indistinguishable from a public key and must pass this check, got: %v", err)
	}
}

// TestLooksLikePrivateKeyFlagsClampedSample relies on samplePubKeyA
// happening to satisfy wg genkey's clamping (verified by hand: its first
// byte is a multiple of 8 and its last byte's top two bits are 0b01) —
// a ~1/16 coincidence for a fixed constant, not evidence the heuristic
// is meaningful on its own; TestLooksLikePrivateKeyFlagsRealPrivateKey
// below is what actually exercises it against real wg genkey output.
func TestLooksLikePrivateKeyFlagsClampedSample(t *testing.T) {
	if !looksLikePrivateKey(samplePubKeyA) {
		t.Fatal("expected samplePubKeyA (known to satisfy wg genkey's clamping) to be flagged")
	}
}

func TestLooksLikePrivateKeyDoesNotFlagNonClampedSample(t *testing.T) {
	if looksLikePrivateKey(samplePubKeyB) {
		t.Fatal("expected samplePubKeyB (known not to satisfy wg genkey's clamping) not to be flagged")
	}
}

func TestLooksLikePrivateKeyFlagsRealPrivateKey(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Skipf("wg not available to generate a real private key: %v", err)
	}
	if !looksLikePrivateKey(priv) {
		t.Fatalf("expected a real wg-genkey private key to be flagged by its clamping structure")
	}
}

func TestLooksLikePrivateKeyRejectsMalformedInput(t *testing.T) {
	for _, key := range []string{"", "not-valid-base64!!!", "dG9vc2hvcnQ="} {
		if looksLikePrivateKey(key) {
			t.Errorf("looksLikePrivateKey(%q) = true, want false for malformed input", key)
		}
	}
}

func TestValidateEndpointValid(t *testing.T) {
	for _, ep := range []string{"vps.example.com:60217", "203.0.113.5:1", "203.0.113.5:65535"} {
		if err := validateEndpoint(ep); err != nil {
			t.Fatalf("validateEndpoint(%q): unexpected error: %v", ep, err)
		}
	}
}

func TestValidateEndpointInvalid(t *testing.T) {
	for _, ep := range []string{
		"no-port-here",
		"host:",
		"host:abc",
		"host:0",
		"host:65536",
		"host:-1",
		":60217",
	} {
		if err := validateEndpoint(ep); err == nil {
			t.Errorf("validateEndpoint(%q): expected an error, got nil", ep)
		}
	}
}

func TestParseRemoteExecTemplateDefault(t *testing.T) {
	got, err := parseRemoteExecTemplate("ssh {}", "vps.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ssh", "vps.example.com"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseRemoteExecTemplateNonTrailingPlaceholder(t *testing.T) {
	got, err := parseRemoteExecTemplate("my-bastion-wrapper --target {} --verbose", "vps.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"my-bastion-wrapper", "--target", "vps.example.com", "--verbose"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseRemoteExecTemplateSudoExample(t *testing.T) {
	got, err := parseRemoteExecTemplate("ssh {} sudo", "vps.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ssh", "vps.example.com", "sudo"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseRemoteExecTemplateMissingPlaceholder(t *testing.T) {
	if _, err := parseRemoteExecTemplate("ssh", "vps.example.com"); err == nil {
		t.Fatal("expected an error for a template missing {}")
	}
}

func TestParseRemoteExecTemplateDuplicatePlaceholder(t *testing.T) {
	if _, err := parseRemoteExecTemplate("ssh {} {}", "vps.example.com"); err == nil {
		t.Fatal("expected an error for a template with two {} placeholders")
	}
}

func TestParseRemoteExecTemplateEmpty(t *testing.T) {
	if _, err := parseRemoteExecTemplate("", "vps.example.com"); err == nil {
		t.Fatal("expected an error for an empty template")
	}
}

func TestParseRemoteExecTemplateWhitespaceOnly(t *testing.T) {
	if _, err := parseRemoteExecTemplate("   ", "vps.example.com"); err == nil {
		t.Fatal("expected an error for a whitespace-only template")
	}
}

func TestIsSelfPair(t *testing.T) {
	if !isSelfPair(samplePubKeyA, samplePubKeyA) {
		t.Fatal("expected identical keys to be reported as a self-pair")
	}
	if isSelfPair(samplePubKeyA, samplePubKeyB) {
		t.Fatal("expected distinct keys not to be reported as a self-pair")
	}
}

func TestDeriveEndpointStripsUserPrefix(t *testing.T) {
	got := deriveEndpoint("admin@vps.example.com", 3)
	want := "vps.example.com:60220"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDeriveEndpointNoUserPrefix(t *testing.T) {
	got := deriveEndpoint("vps.example.com", 0)
	want := "vps.example.com:60217"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDeriveEndpointBracketsIPv6Host(t *testing.T) {
	got := deriveEndpoint("admin@2001:db8::1", 0)
	want := "[2001:db8::1]:60217"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if err := validateEndpoint(got); err != nil {
		t.Fatalf("derived endpoint %q must itself pass validateEndpoint: %v", got, err)
	}
}

func newTestConfig() *Config {
	return &Config{
		PrivateKey: "unused-in-these-tests",
		RelayIPs:   []string{"203.0.113.1"},
	}
}

func TestPairPeerWritesNewPeer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	if err := PairPeer(cfg, path, samplePubKeyA, "vps.example.com:60217", io.Discard); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PeerPublicKey != samplePubKeyA {
		t.Fatalf("PeerPublicKey = %q, want %q", got.PeerPublicKey, samplePubKeyA)
	}
	if got.PeerEndpoint != "vps.example.com:60217" {
		t.Fatalf("PeerEndpoint = %q, want vps.example.com:60217", got.PeerEndpoint)
	}
}

func TestPairPeerRejectsInvalidPublicKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	if err := PairPeer(cfg, path, "not-a-valid-key", "", io.Discard); err == nil {
		t.Fatal("expected an error for an invalid public key")
	}
	if cfg.PeerPublicKey != "" {
		t.Fatalf("PeerPublicKey should be untouched after a rejected write, got %q", cfg.PeerPublicKey)
	}
}

func TestPairPeerRejectsInvalidEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	if err := PairPeer(cfg, path, samplePubKeyA, "not-an-endpoint", io.Discard); err == nil {
		t.Fatal("expected an error for an invalid endpoint")
	}
	if cfg.PeerPublicKey != "" {
		t.Fatalf("PeerPublicKey should be untouched when --endpoint fails validation, got %q", cfg.PeerPublicKey)
	}
}

// TestPairPeerIdempotentNoWriteWhenUnchanged mirrors
// TestWriteWatchUnitIfChangedLeavesUpToDateContentAlone's mtime-based
// no-op check (lifecycle_test.go) — the exit criterion this guards is
// "re-running pair run twice doesn't needlessly rewrite the file."
func TestPairPeerIdempotentNoWriteWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}
	if err := PairPeer(cfg, path, samplePubKeyB, "vps.example.com:60217", io.Discard); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	var notices bytes.Buffer
	if err := PairPeer(cfg, path, samplePubKeyB, "vps.example.com:60217", &notices); err != nil {
		t.Fatal(err)
	}

	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("expected a repeat call with identical arguments to leave the file untouched, but it was rewritten")
	}
	if notices.Len() != 0 {
		t.Fatalf("expected no notice on an idempotent no-op repeat, got: %q", notices.String())
	}
}

func TestPairPeerReplacesExistingPeer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	cfg.PeerPublicKey = samplePubKeyA
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	var notices bytes.Buffer
	if err := PairPeer(cfg, path, samplePubKeyB, "", &notices); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.PeerPublicKey != samplePubKeyB {
		t.Fatalf("PeerPublicKey = %q, want %q (the replacement)", got.PeerPublicKey, samplePubKeyB)
	}
	if !strings.Contains(notices.String(), "replacing existing peer") {
		t.Fatalf("expected a replacement notice when overwriting a different, non-empty peer, got: %q", notices.String())
	}
}

// TestPairPeerWarnsWhenPublicKeyLooksLikePrivateKey covers the case the
// plan's exit criteria call "a private key passed where a public key was
// expected" (see looksLikePrivateKey): validation still accepts the
// value (format alone can't tell the difference), but a warning is
// printed rather than silence.
func TestPairPeerWarnsWhenPublicKeyLooksLikePrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	var notices bytes.Buffer
	if err := PairPeer(cfg, path, samplePubKeyA, "", &notices); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(notices.String(), "looks like it might be a WireGuard *private* key") {
		t.Fatalf("expected a private-key-shaped warning, got: %q", notices.String())
	}
}

func TestPairPeerNoWarningForOrdinaryPublicKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "0.json")
	cfg := newTestConfig()
	if err := persistConfig(cfg, path); err != nil {
		t.Fatal(err)
	}

	var notices bytes.Buffer
	if err := PairPeer(cfg, path, samplePubKeyB, "", &notices); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(notices.String(), "private") {
		t.Fatalf("expected no private-key warning for an ordinary public key, got: %q", notices.String())
	}
}
