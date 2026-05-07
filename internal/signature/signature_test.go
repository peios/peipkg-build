package signature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// projectRoot points at the peipkg-build repo root.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func TestLoadPrivateKeyPEM(t *testing.T) {
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.ed25519")
	priv, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
}

func TestLoadPublicKeyPEM(t *testing.T) {
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.pub")
	data, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestParsePrivateKeyRawSeed(t *testing.T) {
	// 32 zero bytes is a valid (insecure) raw seed.
	seed := make([]byte, ed25519.SeedSize)
	priv, err := ParsePrivateKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("derived private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	// Sanity: signing and verifying round-trips with the derived public key.
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("seed-derived key did not round-trip sign/verify")
	}
}

func TestParsePrivateKeyRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"truncated raw seed (31 bytes)", make([]byte, 31)},
		{"oversized raw seed (33 bytes)", make([]byte, 33)},
		{"garbage", []byte("this is not a key")},
		{"wrong PEM type", []byte("-----BEGIN CERTIFICATE-----\nMIICert...\n-----END CERTIFICATE-----\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrivateKey(tc.data); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestFingerprintRoundTrip(t *testing.T) {
	// The fingerprint is sha256 of the raw public key bytes — we don't pin
	// to a specific value for arbitrary inputs, but we can verify the
	// committed test key produces the expected length and is hex-encoded.
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.pub")
	data, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	fp := Fingerprint(pub)
	if len(fp) != 64 {
		t.Errorf("fingerprint length %d, want 64", len(fp))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Errorf("fingerprint is not valid hex: %v", err)
	}
	if strings.ToLower(fp) != fp {
		t.Errorf("fingerprint must be lowercase hex, got %q", fp)
	}
}

// TestSignDeterministic verifies that Ed25519 signatures are reproducible:
// the same digest signed with the same key produces byte-identical
// envelopes. This is the §5.1.4 reproducibility guarantee.
func TestSignDeterministic(t *testing.T) {
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.ed25519")
	priv, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}

	digest := bytes.Repeat([]byte{0x42}, 32)

	a := Sign(priv, digest)
	b := Sign(priv, digest)
	if a != b {
		t.Errorf("Sign produced non-deterministic envelope:\n a: %+v\n b: %+v", a, b)
	}
}

// TestSignVerifies confirms the produced signature actually verifies with
// the corresponding public key — sanity that we are signing the digest
// directly, not some derived form.
func TestSignVerifies(t *testing.T) {
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.ed25519")
	priv, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}

	digest := bytes.Repeat([]byte{0xab}, 32)
	env := Sign(priv, digest)

	sigBytes, err := base64.RawStdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, digest, sigBytes) {
		t.Error("envelope signature did not verify against the corresponding public key")
	}

	// Fingerprint in the envelope must match the public key's fingerprint.
	if env.KeyFingerprint != Fingerprint(pub) {
		t.Errorf("envelope key_fingerprint = %q, want %q", env.KeyFingerprint, Fingerprint(pub))
	}
}

func TestEncodeShape(t *testing.T) {
	env := Envelope{
		SchemaVersion:  1,
		Algorithm:      Algorithm,
		KeyFingerprint: strings.Repeat("a", 64),
		Signature:      base64.RawStdEncoding.EncodeToString(make([]byte, 64)),
	}
	out, err := Encode(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(out, []byte("\n")) {
		t.Error("envelope JSON missing trailing newline")
	}

	wantOrder := []string{
		`"schema_version"`, `"algorithm"`, `"key_fingerprint"`, `"signature"`,
	}
	s := string(out)
	last := -1
	for _, k := range wantOrder {
		i := strings.Index(s, k)
		if i < 0 {
			t.Errorf("missing %s in output:\n%s", k, s)
			continue
		}
		if i <= last {
			t.Errorf("field %s out of order", k)
		}
		last = i
	}
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
