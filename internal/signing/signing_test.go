package signing

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Spec §5 test 1: the key is created once with the stated modes and read back identically.
func TestLoadOrCreate_CreatesOnceWithTightModes(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	dir := filepath.Join(t.TempDir(), "keys")
	k1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "install.key")); fi.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v, want 0600", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(filepath.Join(dir, "install.pub")); fi.Mode().Perm() != 0o644 {
		t.Errorf("public key mode %v, want 0644", fi.Mode().Perm())
	}
	if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
		t.Errorf("keys dir mode %v, want 0700", di.Mode().Perm())
	}
	k2, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.Public(), k2.Public()) {
		t.Fatal("the second load returned a different key — the first was not persisted, or was overwritten")
	}
	pub, err := ReadPublic(dir)
	if err != nil || !bytes.Equal(pub, k1.Public()) {
		t.Fatalf("ReadPublic: %v", err)
	}
	if fp := Fingerprint(pub); len(fp) != len("sha256:")+16 {
		t.Errorf("fingerprint %q has the wrong shape", fp)
	}
}

func TestSignVerify_RoundTripAndTamper(t *testing.T) {
	t.Setenv(EnvPrivateKey, "")
	k, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"a":1}`)
	sig := k.Sign(msg)
	if !Verify(k.Public(), msg, sig) {
		t.Fatal("a fresh signature does not verify")
	}
	if Verify(k.Public(), []byte(`{"a":2}`), sig) {
		t.Fatal("a changed message verifies")
	}
	other, _ := LoadOrCreate(t.TempDir())
	if Verify(other.Public(), msg, sig) {
		t.Fatal("another install's key verifies this install's signature")
	}
	enc := EncodeSignature(sig)
	dec, err := DecodeSignature(enc)
	if err != nil || !bytes.Equal(dec, sig) {
		t.Fatalf("signature encoding round trip: %v", err)
	}
	if _, err := DecodeSignature("not-a-signature"); err == nil {
		t.Fatal("garbage decoded as a signature")
	}
}

// A CI runner signs with the key the operator provides in the environment; the files are not consulted.
func TestLoadOrCreate_EnvironmentWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvPrivateKey, "")
	k, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "install.key"))
	t.Setenv(EnvPrivateKey, string(b))
	other, err := LoadOrCreate(t.TempDir()) // an EMPTY dir: nothing to read, nothing created
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(other.Public(), k.Public()) {
		t.Fatal("the environment key was not used")
	}
	t.Setenv(EnvPrivateKey, "garbage")
	if _, err := LoadOrCreate(t.TempDir()); err == nil {
		t.Fatal("a malformed environment key was accepted")
	}
}

// THE FILE AN AUDITOR ACTUALLY SAVES.
//
// `shoalcheck evidence pubkey` prints a block: the fingerprint, the key, and five lines telling the reader what a
// signature does and does not say. The obvious shell move —
//
//	$ shoalcheck evidence pubkey > install.pub
//	$ shoalcheck evidence verify --pack ./pack --pub install.pub
//	error: not an ed25519 public key (base64url, 32 bytes)
//
// — fails, because ReadPublic trimmed the whole file and decoded it as one token. The product's own two
// verbs disagreed about what install.pub is, and the refusal named the FORMAT without naming the FIX, on the
// one path walked by the least technical reader in the flow: the auditor who received the block by email.
//
// A public key is not a secret and accepting it out of an explanatory block costs nothing — as long as the
// case that is ambiguous stays refused. Exactly one line that parses is the key; two are a refusal, because
// picking one of them would be a choice nobody made. Verify prints the fingerprint it verified against, so
// the key that was accepted is always named back to the reader.
func TestReadPublic_TakesTheKeyOutOfTheBlockThePubkeyVerbPrints(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString(key.Public())

	block := "sha256:6401d79022cb5aea\n" + enc + "\n\nThe two lines above are the public half of the key that " +
		"signs this install's evidence packs\nand history snapshots. Send them to whoever verifies a pack.\n"
	path := filepath.Join(dir, "install.pub")
	if err := os.WriteFile(path, []byte(block), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPublic(path)
	if err != nil {
		t.Fatalf("the block this product prints was refused as a key file: %v", err)
	}
	if !got.Equal(key.Public()) {
		t.Error("the key read out of the block is not the one the block carries")
	}

	// A BARE KEY STILL READS — that is what keygen writes and what the pack's own instructions describe.
	bare := filepath.Join(dir, "bare.pub")
	if err := os.WriteFile(bare, []byte(enc+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadPublic(bare); err != nil || !got.Equal(key.Public()) {
		t.Errorf("a bare key file stopped reading: %v", err)
	}

	// TWO KEYS IN ONE FILE IS A REFUSAL, and the refusal says how many it found rather than naming a format.
	other, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	two := filepath.Join(dir, "two.pub")
	body := enc + "\n" + base64.RawURLEncoding.EncodeToString(other.Public()) + "\n"
	if err := os.WriteFile(two, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadPublic(two)
	if err == nil {
		t.Error("a file carrying two different public keys was accepted; which one verified would be a " +
			"choice nobody made")
	} else if !strings.Contains(err.Error(), "2") {
		t.Errorf("the refusal does not say how many keys it found: %v", err)
	}

	// AND A FILE WITH NO KEY AT ALL keeps naming the format, because there is nothing else to say.
	none := filepath.Join(dir, "none.pub")
	if err := os.WriteFile(none, []byte("this is not a key\nnor is this\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublic(none); err == nil || !strings.Contains(err.Error(), "ed25519") {
		t.Errorf("a file with no key did not name the format: %v", err)
	}
}
