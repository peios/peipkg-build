// Package files defines the JSON schema and canonical encoding for a peipkg
// per-file integrity manifest (PSD-009 §3.5.1).
//
// As with the package manifest, struct field declaration order is the on-wire
// byte order; do not reorder fields without amending the spec.
package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

// SchemaVersion is the integrity-manifest schema version this package emits.
const SchemaVersion = 1

// Algorithm is the hash algorithm identifier this package emits and accepts.
// PSD-009 v0.22 supports SHA-256 only; other values exist as syntactic
// reservations for future algorithm-agility (§3.5.6).
const Algorithm = "sha256"

// Manifest is the document at .peipkg/files.json.
//
// One Entry MUST be present per regular-file payload entry in the tar archive
// (§3.5.1.3). Directories, symlinks, and metadata entries under .peipkg/ MUST
// NOT appear here.
type Manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Algorithm     string  `json:"algorithm"`
	Entries       []Entry `json:"entries"`
}

// Entry is one row in the integrity manifest. Path is identical to the
// corresponding tar entry path. Hash is the lowercase hex SHA-256 of the
// file's content body.
type Entry struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Hash string `json:"hash"`
}

// HashFile streams r through SHA-256 and returns the lowercase hex digest
// alongside the byte count. r is consumed in full.
func HashFile(r io.Reader) (hash string, size int64, err error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// Encode returns the canonical on-wire form of m: compact JSON with no HTML
// escaping, terminated by a single newline.
//
// A nil Entries field is normalized to an empty array so it encodes as `[]`
// rather than `null` — packages with no regular-file payload entries are
// permitted (§3.2.10) and emit an empty array.
//
// Encode does NOT sort or validate. Callers must pre-sort Entries
// lexicographically by Path (§3.5.1.3) and ensure exactly one entry per
// regular-file payload tar entry (§3.5.1.4).
func Encode(m Manifest) ([]byte, error) {
	if m.Entries == nil {
		m.Entries = []Entry{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
