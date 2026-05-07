package recipe

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// projectRoot returns the repository-relative path containing testdata/.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func TestLoadHelloNoarch(t *testing.T) {
	root := projectRoot(t)
	path := filepath.Join(root, "testdata", "cases", "hello-noarch", "recipe", "peipkg.toml")

	r, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if r.Meta.License != "CC0-1.0" {
		t.Errorf("license = %q, want CC0-1.0", r.Meta.License)
	}
	if r.Meta.Homepage != "https://peios.org" {
		t.Errorf("homepage = %q", r.Meta.Homepage)
	}
	if r.Meta.BuildScript != "build.sh" {
		t.Errorf("build_script = %q", r.Meta.BuildScript)
	}
	if len(r.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(r.Packages))
	}
	p := r.Packages[0]
	if p.Name != "hello" {
		t.Errorf("name = %q", p.Name)
	}
	if p.Architecture != "noarch" {
		t.Errorf("architecture = %q", p.Architecture)
	}
	if len(p.Files) != 1 || p.Files[0] != "usr/share/hello/MESSAGE" {
		t.Errorf("files = %v", p.Files)
	}
}

func TestValidateRequiresBuildScript(t *testing.T) {
	r := Recipe{
		Packages: []Package{{Name: "x", Architecture: "noarch"}},
	}
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "build_script") {
		t.Errorf("Validate error = %v, want one mentioning build_script", err)
	}
}

func TestValidateRequiresAtLeastOnePackage(t *testing.T) {
	r := Recipe{Meta: Meta{BuildScript: "x.sh"}}
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "[[package]]") {
		t.Errorf("Validate error = %v, want one mentioning [[package]]", err)
	}
}

func TestValidateRejectsDuplicatePackageNames(t *testing.T) {
	r := Recipe{
		Meta: Meta{BuildScript: "x.sh"},
		Packages: []Package{
			{Name: "foo", Architecture: "noarch"},
			{Name: "foo", Architecture: "noarch"},
		},
	}
	err := r.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("Validate error = %v, want one mentioning duplicate", err)
	}
}

// TestLoadAcceptsForeignTopLevelSections verifies the parser tolerates
// unknown top-level sections — these are reserved for other tools that
// share the recipe file (notably peipkg-manager's [upstream] and
// [watch] sections).
func TestLoadAcceptsForeignTopLevelSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peipkg.toml")
	body := `
[meta]
license = "MIT"
build_script = "build.sh"

[[package]]
name = "x"
architecture = "noarch"

# Sections not owned by peipkg-build — must NOT cause a parse error.
[upstream]
git = "https://example.com/x.git"
tag_pattern = "^v(\\d+)$"

[watch]
poll_interval = "1h"

[anything-else]
foo = "bar"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := Load(path)
	if err != nil {
		t.Fatalf("Load rejected recipe with foreign top-level sections: %v", err)
	}
	if r.Meta.License != "MIT" {
		t.Errorf("Meta.License = %q, want MIT", r.Meta.License)
	}
	if len(r.Packages) != 1 || r.Packages[0].Name != "x" {
		t.Errorf("expected exactly one package named x, got %v", r.Packages)
	}
}

// TestLoadRejectsUnknownKeysInMeta verifies the typo guard still fires
// for keys that ARE under sections peipkg-build owns.
func TestLoadRejectsUnknownKeysInMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peipkg.toml")
	body := `
[meta]
license = "MIT"
build_script = "build.sh"
homepag = "typo"   # typo of homepage

[[package]]
name = "x"
architecture = "noarch"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted recipe with typo in [meta]")
	}
	if !strings.Contains(err.Error(), "homepag") {
		t.Errorf("error did not mention the typo'd key: %v", err)
	}
}

// TestLoadRejectsUnknownKeysInPackage verifies the typo guard fires for
// keys nested under [[package]] too.
func TestLoadRejectsUnknownKeysInPackage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peipkg.toml")
	body := `
[meta]
license = "MIT"
build_script = "build.sh"

[[package]]
name = "x"
architecture = "noarch"
fles = ["usr/bin/x"]   # typo of files
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("Load accepted recipe with typo in [[package]]")
	}
	if !strings.Contains(err.Error(), "fles") {
		t.Errorf("error did not mention the typo'd key: %v", err)
	}
}
