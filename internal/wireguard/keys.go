// Package wireguard manages WireGuard keys and the local WireGuard network
// interface (creation, configuration).
package wireguard

import (
	"github.com/Rose-Vibe/wganchor/internal/config"
	"github.com/Rose-Vibe/wganchor/internal/sysexec"
)

// GenerateKeypair shells out to `wg genkey` / `wg pubkey`. The private key
// is captured from stdout and fed to `wg pubkey` over stdin — it never
// touches argv, per docs/arch/wireguard.md.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	priv, err := sysexec.RunCmd("wg", "genkey")
	if err != nil {
		return "", "", err
	}
	pub, err := PublicKeyFromPrivate(priv)
	if err != nil {
		return "", "", err
	}
	return priv, pub, nil
}

// PublicKeyFromPrivate derives a public key from a private key via
// `wg pubkey`, feeding the key over stdin rather than argv.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	return sysexec.RunCmdStdin(privateKey, "wg", "pubkey")
}

// EnsureKeys self-provisions a keypair into cfg if it doesn't already have
// one, persisting the generated private key back to path (preserving the
// file's existing 0600 mode). Returns the public key either way (derived
// from the existing key, or the newly generated one) so the caller can
// print it for the operator to hand to the other side, and whether a new
// key was generated.
func EnsureKeys(cfg *config.Config, path string) (publicKey string, generated bool, err error) {
	if cfg.PrivateKey != "" {
		pub, err := PublicKeyFromPrivate(cfg.PrivateKey)
		return pub, false, err
	}

	priv, pub, err := GenerateKeypair()
	if err != nil {
		return "", false, err
	}
	cfg.PrivateKey = priv
	if err := config.Persist(cfg, path); err != nil {
		return "", false, err
	}
	return pub, true, nil
}
