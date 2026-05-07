// Package signature implements the §5.1 package signature: the on-wire
// envelope schema, key parsing, fingerprint computation, and the Sign
// helper that turns a hash + private key into a serialised envelope.
//
// This package is producer-side only. It does not verify signatures;
// consumer-side verification belongs in install-time tooling.
package signature

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

// EntryPath is the tar archive path of the signature entry (§5.1.1).
const EntryPath = ".peipkg/signature"

// SchemaVersion is the envelope schema version this package emits.
const SchemaVersion = 1

// Algorithm is the signature algorithm identifier this package emits and
// accepts. PSD-009 v0.22 supports Ed25519 only (§5.2.1); other algorithm
// values are reserved for future versions and MUST be rejected by a v0.22
// implementation.
const Algorithm = "ed25519"

// Envelope is the JSON document stored at .peipkg/signature.
//
// Field declaration order is the on-wire order — encoding/json marshals in
// declaration order, and §5.1.3 mandates strict envelope shape (no extra
// fields, ordered fields). Reordering changes the bytes a producer emits.
type Envelope struct {
	SchemaVersion  int    `json:"schema_version"`
	Algorithm      string `json:"algorithm"`
	KeyFingerprint string `json:"key_fingerprint"`
	Signature      string `json:"signature"`
}

// Sign produces a complete envelope for the given digest. digest is the
// SHA-256 of the uncompressed tar bytes preceding the signature entry
// (§5.1.2), exactly 32 bytes; pack computes it.
func Sign(privKey ed25519.PrivateKey, digest []byte) Envelope {
	pub := privKey.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(privKey, digest)
	return Envelope{
		SchemaVersion:  SchemaVersion,
		Algorithm:      Algorithm,
		KeyFingerprint: Fingerprint(pub),
		Signature:      base64.RawStdEncoding.EncodeToString(sig),
	}
}

// Fingerprint computes the canonical key fingerprint defined in §5.2.3:
// the lowercase hex SHA-256 of the raw 32-byte public key.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// Encode produces the canonical on-wire JSON of e: compact, no HTML
// escaping, single trailing newline. The encoding matches the manifest
// and integrity-manifest encoders used elsewhere.
func Encode(e Envelope) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// LoadPrivateKey reads an Ed25519 private key from a file. See
// ParsePrivateKey for the accepted on-disk encodings.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key %s: %w", path, err)
	}
	key, err := ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", path, err)
	}
	return key, nil
}

// ParsePrivateKey decodes an Ed25519 private key from one of two on-disk
// encodings:
//
//   - A raw 32-byte seed (no header, no encoding). Per RFC 8032 §5.1.5,
//     the seed is the canonical compact representation of an Ed25519
//     private key; the full 64-byte expanded form is derived from it.
//
//   - A PEM-encoded `PRIVATE KEY` block in PKCS#8 form (RFC 5958), the
//     standard PEM container produced by openssl genpkey -algorithm ed25519.
//
// The two forms are distinguished by content: anything ed25519.SeedSize
// bytes long is treated as a raw seed; anything else is parsed as PEM.
// PEM keys whose embedded type is not Ed25519 are rejected.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key is neither a %d-byte raw seed nor a PEM block", ed25519.SeedSize)
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("PEM block type is %q, expected PRIVATE KEY (PKCS#8)", block.Type)
	}

	pk, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 PRIVATE KEY: %w", err)
	}

	edKey, ok := pk.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is %T, not ed25519.PrivateKey", pk)
	}
	return edKey, nil
}

// ParsePublicKey decodes an Ed25519 public key from either:
//
//   - A raw 32-byte public key value, or
//   - A PEM-encoded `PUBLIC KEY` block in SubjectPublicKeyInfo form (RFC 5280).
//
// The two forms are distinguished by content. This is the consumer-side
// counterpart to ParsePrivateKey; producers don't need it for signing,
// but tests and verifiers do.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == ed25519.PublicKeySize {
		out := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(out, data)
		return out, nil
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("key is neither a %d-byte raw public key nor a PEM block", ed25519.PublicKeySize)
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("PEM block type is %q, expected PUBLIC KEY", block.Type)
	}

	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX PUBLIC KEY: %w", err)
	}

	edKey, ok := pk.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM key is %T, not ed25519.PublicKey", pk)
	}
	return edKey, nil
}
