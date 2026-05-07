// Package recipe parses a peipkg.toml recipe.
//
// The recipe is the authoring surface used by package maintainers; the build
// farm supplies the version, source ref, farm id, and timestamp on the CLI.
// See peipkg-build/DESIGN.md for the recipe schema.
//
// Recipe types are intentionally separate from the manifest types in
// internal/manifest. The recipe carries authoring conveniences that do not
// appear on the wire (e.g. the SameBuild shorthand), and the manifest is the
// normative on-wire schema. The pack stage converts one to the other.
package recipe

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Recipe is a parsed peipkg.toml.
type Recipe struct {
	Meta     Meta      `toml:"meta"`
	Packages []Package `toml:"package"`
}

// Meta carries facts shared across every output package: license, upstream
// pointers, and the build script entry point.
type Meta struct {
	License     string `toml:"license"`
	Homepage    string `toml:"homepage"`
	Source      string `toml:"source"`       // informational only; not consumed by the tool
	BuildScript string `toml:"build_script"` // path relative to the recipe directory
}

// Package is one [[package]] stanza. Each stanza becomes one output .peipkg.
type Package struct {
	Name                 string       `toml:"name"`
	Architecture         string       `toml:"architecture"`
	Description          string       `toml:"description"`
	Dependencies         []Dependency `toml:"dependencies"`
	OptionalDependencies []Dependency `toml:"optional_dependencies"`
	Conflicts            []Dependency `toml:"conflicts"`
	Provides             []Provides   `toml:"provides"`
	Replaces             []Replaces   `toml:"replaces"`
	SideEffects          []string     `toml:"side_effects"`
	Files                []string     `toml:"files"` // doublestar glob patterns relative to $DESTDIR
}

// Dependency is a recipe-level dependency entry. SameBuild is a recipe
// shorthand: when true, the build stage rewrites the entry to a strict
// version-equality constraint pinned to this build's version. The shorthand
// does not appear on the wire — manifest.Dependency has no SameBuild field.
type Dependency struct {
	Name       string `toml:"name"`
	Constraint string `toml:"constraint"`
	Arch       string `toml:"arch"`
	SameBuild  bool   `toml:"same_build"`
}

type Provides struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type Replaces struct {
	Name       string `toml:"name"`
	Constraint string `toml:"constraint"`
}

// Load reads and parses a recipe from path. Unknown TOML keys are rejected
// so that typos in field names surface as parse errors rather than silently-
// dropped fields.
func Load(path string) (Recipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Recipe{}, fmt.Errorf("read recipe %s: %w", path, err)
	}

	var r Recipe
	md, err := toml.Decode(string(data), &r)
	if err != nil {
		return Recipe{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if extras := md.Undecoded(); len(extras) > 0 {
		return Recipe{}, fmt.Errorf("parse %s: unknown keys %v", path, extras)
	}

	if err := r.Validate(); err != nil {
		return Recipe{}, fmt.Errorf("validate %s: %w", path, err)
	}
	return r, nil
}

// Validate checks structural invariants of the recipe. It does not validate
// glob syntax (the pack stage does that) or that referenced fields conform
// to PSD-009 §2 identity rules (the manifest builder does that).
func (r Recipe) Validate() error {
	if r.Meta.BuildScript == "" {
		return fmt.Errorf("[meta].build_script is required")
	}
	if len(r.Packages) == 0 {
		return fmt.Errorf("recipe must declare at least one [[package]]")
	}

	seen := make(map[string]struct{}, len(r.Packages))
	for i, p := range r.Packages {
		if p.Name == "" {
			return fmt.Errorf("[[package]] #%d: name is required", i)
		}
		if p.Architecture == "" {
			return fmt.Errorf("[[package]] %s: architecture is required", p.Name)
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("[[package]] %s: duplicate name", p.Name)
		}
		seen[p.Name] = struct{}{}

		for j, d := range p.Dependencies {
			if d.Name == "" {
				return fmt.Errorf("[[package]] %s: dependencies[%d]: name is required", p.Name, j)
			}
		}
		for j, d := range p.OptionalDependencies {
			if d.Name == "" {
				return fmt.Errorf("[[package]] %s: optional_dependencies[%d]: name is required", p.Name, j)
			}
		}
		for j, d := range p.Conflicts {
			if d.Name == "" {
				return fmt.Errorf("[[package]] %s: conflicts[%d]: name is required", p.Name, j)
			}
		}
	}
	return nil
}
