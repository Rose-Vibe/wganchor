package config

import "testing"

func baseValidConfig() *Config {
	return &Config{
		PeerPublicKey: "9+FmgsgEbMU5fsZNHls5o5Elt75vM25WZoIPd5d73lU=",
		PeerEndpoint:  "203.0.113.10:60217",
		RelayIPs:      []string{"203.0.113.20"},
	}
}

func TestValidateConfigServerOK(t *testing.T) {
	cfg := baseValidConfig()
	cfg.PeerEndpoint = "" // server has no endpoint to dial
	if err := ValidateConfig(cfg, "server"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfigClientOK(t *testing.T) {
	if err := ValidateConfig(baseValidConfig(), "client"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfigRejectsMissingPeerPublicKey(t *testing.T) {
	cfg := baseValidConfig()
	cfg.PeerPublicKey = ""
	if err := ValidateConfig(cfg, "client"); err == nil {
		t.Fatal("expected an error for missing peer_public_key")
	}
}

func TestValidateConfigRejectsMissingPeerEndpointOnClient(t *testing.T) {
	cfg := baseValidConfig()
	cfg.PeerEndpoint = ""
	if err := ValidateConfig(cfg, "client"); err == nil {
		t.Fatal("expected an error for missing peer_endpoint on client")
	}
}

func TestValidateConfigAllowsMissingPeerEndpointOnServer(t *testing.T) {
	cfg := baseValidConfig()
	cfg.PeerEndpoint = ""
	if err := ValidateConfig(cfg, "server"); err != nil {
		t.Fatalf("server should not require peer_endpoint: %v", err)
	}
}

func TestValidateConfigRejectsEmptyRelayIPs(t *testing.T) {
	cfg := baseValidConfig()
	cfg.RelayIPs = nil
	if err := ValidateConfig(cfg, "server"); err == nil {
		t.Fatal("expected an error for empty relay_ips")
	}
	if err := ValidateConfig(cfg, "client"); err == nil {
		t.Fatal("expected an error for empty relay_ips on client too")
	}
}

func TestValidateConfigRejectsMalformedRelayIP(t *testing.T) {
	cfg := baseValidConfig()
	cfg.RelayIPs = []string{"203.0.113.20", "not-an-ip"}
	if err := ValidateConfig(cfg, "server"); err == nil {
		t.Fatal("expected an error for a malformed relay IP")
	}
}

func TestValidateConfigAcceptsMultipleRelayIPs(t *testing.T) {
	cfg := baseValidConfig()
	cfg.RelayIPs = []string{"203.0.113.20", "108.61.192.115"}
	if err := ValidateConfig(cfg, "server"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateConfigRejectsIPv6RelayIP(t *testing.T) {
	cfg := baseValidConfig()
	cfg.RelayIPs = []string{"2001:db8::1"}
	if err := ValidateConfig(cfg, "server"); err == nil {
		t.Fatal("expected an error for an IPv6 relay IP (unsupported)")
	}
}

func TestValidateConfigRejectsDuplicateRelayIP(t *testing.T) {
	cfg := baseValidConfig()
	cfg.RelayIPs = []string{"203.0.113.20", "203.0.113.20"}
	if err := ValidateConfig(cfg, "server"); err == nil {
		t.Fatal("expected an error for a duplicate relay IP")
	}
}

// TestValidateRelayIP guards the extraction internal/relay's
// Add/Remove (relay add/remove) depend on: ValidateConfig's own tests above must
// keep passing unmodified against this extracted version, proving the
// extraction didn't change its behavior; this test covers ValidateRelayIP
// directly, standalone.
func TestValidateRelayIP(t *testing.T) {
	if err := ValidateRelayIP("203.0.113.20"); err != nil {
		t.Fatalf("expected a valid IPv4 to pass, got %v", err)
	}
	if err := ValidateRelayIP("2001:db8::1"); err == nil {
		t.Fatal("expected an error for an IPv6 address (unsupported)")
	}
	if err := ValidateRelayIP("not-an-ip"); err == nil {
		t.Fatal("expected an error for garbage input")
	}
	if err := ValidateRelayIP(""); err == nil {
		t.Fatal("expected an error for an empty string")
	}
}
