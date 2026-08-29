package main

import (
	"reflect"
	"testing"
)

func TestAllowedIPsForRoleClientIsWideOpen(t *testing.T) {
	cfg := &Config{RelayIPs: []string{"203.0.113.20"}}
	got := AllowedIPsForRole(cfg, "client")
	want := []string{"0.0.0.0/0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAllowedIPsForRoleServerMatchesRelayIPs(t *testing.T) {
	cfg := &Config{RelayIPs: []string{"203.0.113.20", "108.61.192.115"}}
	got := AllowedIPsForRole(cfg, "server")
	want := []string{"203.0.113.20/32", "108.61.192.115/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAllowedIPsForRoleServerSingleRelayIP(t *testing.T) {
	cfg := &Config{RelayIPs: []string{"203.0.113.20"}}
	got := AllowedIPsForRole(cfg, "server")
	want := []string{"203.0.113.20/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
