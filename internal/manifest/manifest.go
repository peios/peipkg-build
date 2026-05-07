// Package manifest defines the JSON schema and canonical encoding for a
// peipkg manifest (PSD-009 §3.3).
//
// The struct field declaration order is normative: encoding/json marshals
// struct fields in declaration order, and that order is the on-wire byte
// order. Reordering fields here changes the bytes a producer emits, which
// breaks reproducibility. Field order MUST track §3.3.
package manifest

import (
	"bytes"
	"encoding/json"
	"time"
)

// SchemaVersion is the manifest schema version this package emits.
const SchemaVersion = 1

// Manifest is the document at .peipkg/manifest.json.
//
// Required fields (§3.3.2) and optional fields (§3.3.3) are both always
// emitted. Always emitting optional fields gives producers a single canonical
// form: a recipe that omits an optional field and one that supplies its empty
// default produce identical output. The spec permits omission of optional
// fields, so a stripped-down manifest would still be valid; we choose the
// always-emit form for byte-stability.
type Manifest struct {
	SchemaVersion        int          `json:"schema_version"`
	Name                 string       `json:"name"`
	Version              string       `json:"version"`
	Architecture         string       `json:"architecture"`
	Description          string       `json:"description"`
	License              string       `json:"license"`
	Homepage             string       `json:"homepage"`
	Dependencies         []Dependency `json:"dependencies"`
	OptionalDependencies []Dependency `json:"optional_dependencies"`
	Conflicts            []Dependency `json:"conflicts"`
	Provides             []Provides   `json:"provides"`
	Replaces             []Replaces   `json:"replaces"`
	SideEffects          []string     `json:"side_effects"`
	SizeInstalled        int64        `json:"size_installed"`
	SDOverrides          []SDOverride `json:"sd_overrides"`
	Build                Build        `json:"build"`
}

// Dependency is one entry in dependencies, optional_dependencies, or conflicts
// (§4.1.1, §4.1.2). Constraint and Arch use omitempty so a bare-name entry
// emits the canonical {"name":"..."} form regardless of whether the recipe
// supplied the empty defaults explicitly.
type Dependency struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
	Arch       string `json:"arch,omitempty"`
}

// Provides is one entry in the provides array (§4.1.4).
type Provides struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Replaces is one entry in the replaces array (§4.1.5).
type Replaces struct {
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
}

// SDOverride is one entry in the sd_overrides array (§3.3.5). Both fields are
// required.
type SDOverride struct {
	Path string `json:"path"`
	SD   string `json:"sd"`
}

// Build is the build-provenance object (§3.3.4). Timestamp MUST be an RFC 3339
// UTC instant with the 'Z' zone designator (§3.3.4).
type Build struct {
	Timestamp string `json:"timestamp"`
	FarmID    string `json:"farm_id"`
	SourceRef string `json:"source_ref"`
}

// ModTime parses Build.Timestamp into the time.Time used for every tar
// entry's modification time (§3.1.4 rule #2). Producers and consumers MUST
// agree on this conversion.
func (b Build) ModTime() (time.Time, error) {
	return time.Parse(time.RFC3339, b.Timestamp)
}

// Encode returns the canonical on-wire form of m: compact JSON with no HTML
// escaping (matching jq -c output), terminated by a single newline character
// (§3.3.7).
//
// nil array fields are normalized to empty arrays so they encode as `[]`
// rather than `null`. The spec treats an absent optional field as equivalent
// to an empty array (§3.3.3); on the wire we always emit the empty-array
// form for byte-stability.
//
// Encode does NOT sort array contents or validate semantics. Callers must
// ensure dependency arrays are lex-sorted by name (§4.1) and that
// sd_overrides is lex-sorted by path (§3.3.5).
func Encode(m Manifest) ([]byte, error) {
	if m.Dependencies == nil {
		m.Dependencies = []Dependency{}
	}
	if m.OptionalDependencies == nil {
		m.OptionalDependencies = []Dependency{}
	}
	if m.Conflicts == nil {
		m.Conflicts = []Dependency{}
	}
	if m.Provides == nil {
		m.Provides = []Provides{}
	}
	if m.Replaces == nil {
		m.Replaces = []Replaces{}
	}
	if m.SideEffects == nil {
		m.SideEffects = []string{}
	}
	if m.SDOverrides == nil {
		m.SDOverrides = []SDOverride{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
