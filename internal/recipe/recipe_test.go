package recipe

import (
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
