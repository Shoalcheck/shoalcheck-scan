// Package signing is the install's own key: one ed25519 pair per machine, created on first use, used to sign the
// readings this install writes and the evidence packs it builds. It is a second key with a different owner from
// the vendor's bundle key (cmd/shoalcheck-refdata keygen signs reference data; this signs the operator's own bytes).
//
// WHAT A SIGNATURE HERE MEANS, AND DOES NOT. A file that verifies against the install's public key is byte for
// byte what the holder of the private key signed; a file that does not has been changed since, or was signed by
// another key. It does not say the reading was truthful, which cluster it read, or which person ran it — and no
// sentence built on it may imply those. The private key is protected exactly as the kubeconfig beside it is.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"github.com/Shoalcheck/shoalcheck-scan/internal/envx"
	"strings"
)

// Key is the install's keypair.
type Key struct {
	priv ed25519.PrivateKey
}

const (
	privateFile = "install.key"
	publicFile  = "install.pub"
	// EnvPrivateKey lets a CI runner sign with a key the operator provides: the private half, base64url without
	// padding — the same encoding cmd/shoalcheck-refdata keygen prints. Absent, a runner's readings are unsigned.
	EnvPrivateKey = "SHOALCHECK_INSTALL_KEY"
)

// LoadOrCreate returns the key in dir, creating it (0700 dir, 0600 private, 0644 public) when absent. The
// environment variable wins over the files, so a CI job can sign without a home directory.
func LoadOrCreate(dir string) (*Key, error) {
	if v := envx.Get(EnvPrivateKey); v != "" {
		return FromBase64(v)
	}
	privPath := filepath.Join(dir, privateFile)
	if b, err := os.ReadFile(privPath); err == nil {
		k, err := FromBase64(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", privPath, err)
		}
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, []byte(base64.RawURLEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, publicFile), []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return nil, err
	}
	return &Key{priv: priv}, nil
}

// FromBase64 decodes a private key as keygen prints it.
func FromBase64(s string) (*Key, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("not an ed25519 private key (base64url, 64 bytes)")
	}
	return &Key{priv: ed25519.PrivateKey(raw)}, nil
}

// PublicFromBase64 decodes a public key as install.pub carries it.
func PublicFromBase64(s string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not an ed25519 public key (base64url, 32 bytes)")
	}
	return ed25519.PublicKey(raw), nil
}

// ReadPublic reads install.pub from a keys directory or a file path.
func ReadPublic(path string) (ed25519.PublicKey, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		path = filepath.Join(path, publicFile)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return publicFromFileBody(string(b))
}

// publicFromFileBody reads the key out of what an auditor actually saved.
//
// `shoalcheck evidence pubkey` prints a BLOCK — a fingerprint, the key, and five lines saying what a signature
// does and does not establish — and tells the reader to save the second line. The obvious shell move saves
// all of it, and `verify --pub` then refused with "not an ed25519 public key (base64url, 32 bytes)": the
// product's own two verbs disagreeing about what install.pub is, on the path walked by the least technical
// reader in the flow.
//
// A public key is not a secret, and taking it out of an explanatory block costs nothing. What is refused is
// AMBIGUITY: two parseable keys in one file is a refusal, because picking one would be a choice nobody made,
// and a file with no key keeps naming the format, because there is nothing else to say. Verify prints the
// fingerprint it verified against, so the key that was accepted is always named back to the reader.
func publicFromFileBody(body string) (ed25519.PublicKey, error) {
	if pub, err := PublicFromBase64(body); err == nil {
		return pub, nil
	}
	var found []ed25519.PublicKey
	for _, ln := range strings.Split(body, "\n") {
		if pub, err := PublicFromBase64(ln); err == nil {
			found = append(found, pub)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, errors.New("not an ed25519 public key (base64url, 32 bytes)")
	default:
		return nil, fmt.Errorf("this file carries %d ed25519 public keys and nothing says which one signed "+
			"the pack; keep the one line `shoalcheck evidence pubkey` names as the key", len(found))
	}
}

// Sign returns the ed25519 signature over msg.
func (k *Key) Sign(msg []byte) []byte { return ed25519.Sign(k.priv, msg) }

// Public returns the public half.
func (k *Key) Public() ed25519.PublicKey { return k.priv.Public().(ed25519.PublicKey) }

// Fingerprint is "sha256:" + the first 16 hex characters of the public key's SHA-256 — short enough to read
// aloud to an auditor, long enough not to collide by accident.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])[:16]
}

// Verify reports whether sig is a valid signature over msg for pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, msg, sig)
}

// EncodeSignature is the sidecar/manifest form: base64url without padding.
func EncodeSignature(sig []byte) string { return base64.RawURLEncoding.EncodeToString(sig) }

// DecodeSignature reverses EncodeSignature.
func DecodeSignature(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("not an ed25519 signature")
	}
	return raw, nil
}
