package builder

import (
	"strings"
	"testing"

	"github.com/peios/peipkg-build/internal/recipe"
)

func TestPartitionAssignsByGlob(t *testing.T) {
	leaves := []leaf{
		{path: "usr/bin/foo", kind: leafFile},
		{path: "usr/lib/libfoo.so.1", kind: leafFile},
		{path: "usr/include/foo.h", kind: leafFile},
	}
	packages := []recipe.Package{
		{Name: "foo", Files: []string{"usr/bin/**"}},
		{Name: "libfoo", Files: []string{"usr/lib/**"}},
		{Name: "libfoo-dev", Files: []string{"usr/include/**"}},
	}

	claims, err := partitionLeaves(leaves, packages)
	if err != nil {
		t.Fatal(err)
	}
	if !claims["foo"]["usr/bin/foo"] {
		t.Error("foo did not claim usr/bin/foo")
	}
	if !claims["libfoo"]["usr/lib/libfoo.so.1"] {
		t.Error("libfoo did not claim usr/lib/libfoo.so.1")
	}
	if !claims["libfoo-dev"]["usr/include/foo.h"] {
		t.Error("libfoo-dev did not claim usr/include/foo.h")
	}
}

func TestPartitionRejectsOrphans(t *testing.T) {
	leaves := []leaf{
		{path: "usr/share/man/man1/orphan.1", kind: leafFile},
	}
	packages := []recipe.Package{
		{Name: "foo", Files: []string{"usr/bin/**"}},
	}

	_, err := partitionLeaves(leaves, packages)
	if err == nil {
		t.Fatal("partitionLeaves accepted orphan path")
	}
	if !strings.Contains(err.Error(), "orphan.1") {
		t.Errorf("orphan error did not name the orphan path: %v", err)
	}
}

func TestPartitionRejectsOverlap(t *testing.T) {
	leaves := []leaf{
		{path: "usr/bin/foo", kind: leafFile},
	}
	packages := []recipe.Package{
		{Name: "foo", Files: []string{"usr/**"}},
		{Name: "foo-also", Files: []string{"**/foo"}},
	}

	_, err := partitionLeaves(leaves, packages)
	if err == nil {
		t.Fatal("partitionLeaves accepted overlapping globs")
	}
	if !strings.Contains(err.Error(), "foo") || !strings.Contains(err.Error(), "foo-also") {
		t.Errorf("overlap error did not name both packages: %v", err)
	}
}

func TestPartitionLiteralPath(t *testing.T) {
	// hello-noarch's recipe uses a literal path (no glob). Make sure that
	// works — not just doublestar-style globs.
	leaves := []leaf{
		{path: "usr/share/hello/MESSAGE", kind: leafFile},
	}
	packages := []recipe.Package{
		{Name: "hello", Files: []string{"usr/share/hello/MESSAGE"}},
	}

	claims, err := partitionLeaves(leaves, packages)
	if err != nil {
		t.Fatal(err)
	}
	if !claims["hello"]["usr/share/hello/MESSAGE"] {
		t.Error("literal path not assigned")
	}
}

func TestTimestampToEpochAcceptsZ(t *testing.T) {
	got, err := timestampToEpoch("2026-05-06T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if got != 1778068800 {
		t.Errorf("epoch = %d, want 1778068800", got)
	}
}

func TestTimestampToEpochRejectsOffset(t *testing.T) {
	_, err := timestampToEpoch("2026-05-06T12:00:00+00:00")
	if err == nil {
		t.Error("timestamp with explicit offset accepted; spec mandates 'Z' suffix")
	}
}

func TestConvertDepsRejectsDuplicate(t *testing.T) {
	cfg := Config{Recipe: recipe.Recipe{}, Version: "1.0-1"}
	_, err := convertDeps([]recipe.Dependency{
		{Name: "libssl"},
		{Name: "libssl"},
	}, cfg, "pkg", "dependencies")
	if err == nil {
		t.Fatal("convertDeps accepted duplicate names")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error did not mention duplicate: %v", err)
	}
}

func TestConvertDepsResolvesSameBuild(t *testing.T) {
	cfg := Config{
		Recipe: recipe.Recipe{
			Packages: []recipe.Package{{Name: "libfoo"}},
		},
		Version: "1.2.3-4",
	}
	deps, err := convertDeps([]recipe.Dependency{
		{Name: "libfoo", SameBuild: true},
	}, cfg, "libfoo-dev", "dependencies")
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 {
		t.Fatalf("got %d deps, want 1", len(deps))
	}
	if deps[0].Constraint != "= 1.2.3-4" {
		t.Errorf("constraint = %q, want %q", deps[0].Constraint, "= 1.2.3-4")
	}
}

func TestConvertDepsRejectsSameBuildOnNonSibling(t *testing.T) {
	cfg := Config{
		Recipe:  recipe.Recipe{Packages: []recipe.Package{{Name: "libfoo"}}},
		Version: "1.0-1",
	}
	_, err := convertDeps([]recipe.Dependency{
		{Name: "libbar", SameBuild: true},
	}, cfg, "libfoo-dev", "dependencies")
	if err == nil {
		t.Error("same_build accepted for non-sibling dep")
	}
}

// runValidate is a small helper that wraps validateClaims for table-driven
// tests below: it builds a one-package claims map and runs validation,
// returning either a successful nil result or the error message.
func runValidate(t *testing.T, pkg recipe.Package, leaves []leaf) error {
	t.Helper()
	claims := map[string]map[string]bool{pkg.Name: {}}
	for _, l := range leaves {
		claims[pkg.Name][l.path] = true
	}
	return validateClaims([]recipe.Package{pkg}, claims, leaves)
}

func TestValidateAcceptsPermittedPaths(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	leaves := []leaf{
		{path: "usr/bin/foo", kind: leafFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: leafFile},
		{path: "usr/share/doc/foo/README", kind: leafFile},
		{path: "usr/include/foo.h", kind: leafFile},
		{path: "etc/foo/foo.conf", kind: leafFile},
		{path: "opt/foo/bin/foo", kind: leafFile},
	}
	if err := runValidate(t, pkg, leaves); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

func TestValidateRejectsForbiddenTopLevel(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	for _, path := range []string{
		"home/user/foo",
		"tmp/foo",
		"srv/data/foo",
		"usr/local/bin/foo",
		"lib/foo.so",
		"sbin/foo",
	} {
		err := runValidate(t, pkg, []leaf{{path: path, kind: leafFile}})
		if err == nil {
			t.Errorf("path %q: expected rejection (not under §3.4.1 destinations)", path)
		}
	}
}

func TestValidateRejectsPopulatedVar(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{{path: "var/log/foo/seed.log", kind: leafFile}})
	if err == nil || !strings.Contains(err.Error(), "/var/") {
		t.Errorf("expected rejection mentioning /var/, got %v", err)
	}
}

func TestValidateRejectsNoarchTriplet(t *testing.T) {
	pkg := recipe.Package{Name: "noarch-bad", Architecture: "noarch"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: leafFile},
	})
	if err == nil || !strings.Contains(err.Error(), "noarch") {
		t.Errorf("expected noarch rejection, got %v", err)
	}
}

func TestValidateRejectsWrongTriplet(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/lib/aarch64-linux-peios/libfoo.so.1", kind: leafFile},
	})
	if err == nil || !strings.Contains(err.Error(), "triplet") {
		t.Errorf("expected wrong-triplet rejection, got %v", err)
	}
}

func TestValidateRejectsBareUsrLib(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/lib/foo.so", kind: leafFile},
	})
	if err == nil || !strings.Contains(err.Error(), "directly under /usr/lib/") {
		t.Errorf("expected /usr/lib direct rejection, got %v", err)
	}
}

func TestValidateAcceptsBootSymlinkAndFile(t *testing.T) {
	// /boot/ is a §3.4.1 permitted destination admitting both real files
	// and symlinks. The SHOULD-be-symlinks rule (§3.4.1) is not enforced
	// at format-validation time. The canonical kernel-package pattern:
	// real bzImage under /usr/lib/<triplet>/, /boot/ symlink for
	// bootloader discovery.
	pkg := recipe.Package{Name: "kernel", Architecture: "x86_64"}
	leaves := []leaf{
		{path: "usr/lib/x86_64-linux-peios/kernel/vmlinuz", kind: leafFile},
		{path: "boot/vmlinuz", kind: leafSymlink, linkTarget: "../usr/lib/x86_64-linux-peios/kernel/vmlinuz"},
	}
	if err := runValidate(t, pkg, leaves); err != nil {
		t.Errorf("expected accept of boot symlink + canonical file, got: %v", err)
	}
}

func TestValidateAcceptsInTreeSymlink(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	leaves := []leaf{
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1.2.3", kind: leafFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so.1", kind: leafSymlink, linkTarget: "libfoo.so.1.2.3"},
	}
	if err := runValidate(t, pkg, leaves); err != nil {
		t.Errorf("expected accept, got: %v", err)
	}
}

func TestValidateAcceptsCrossPackageSymlink(t *testing.T) {
	// A -dev package's libfoo.so points at libfoo.so.1 in the runtime
	// package. Resolved target lands under /usr/lib/<triplet>/, which is
	// a §3.4.1 permitted destination — accept.
	pkg := recipe.Package{Name: "libfoo-dev", Architecture: "x86_64"}
	leaves := []leaf{
		{
			path:       "usr/lib/x86_64-linux-peios/libfoo.so",
			kind:       leafSymlink,
			linkTarget: "libfoo.so.1",
		},
	}
	if err := runValidate(t, pkg, leaves); err != nil {
		t.Errorf("expected accept of cross-package symlink, got: %v", err)
	}
}

func TestValidateRejectsAbsoluteSymlinkTarget(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/share/bad/link", kind: leafSymlink, linkTarget: "/etc/passwd"},
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("expected absolute-target rejection, got %v", err)
	}
}

func TestValidateRejectsSymlinkEscapingPeipkgTree(t *testing.T) {
	// Resolved target lands above the peipkg-managed root entirely
	// (path.Join produces "../foo"). This is the strongest escape: not
	// just outside §3.4.1, but outside the entire relative root.
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "etc/foo", kind: leafSymlink, linkTarget: "../../../bar"},
	})
	if err == nil {
		t.Errorf("expected rejection of target escaping peipkg tree, got nil")
	}
}

// TestValidateAcceptsSymlinkToSystemFileShape documents the format-level
// gap: a symlink whose resolved path lands inside §3.4.1 destinations
// (here, "etc/passwd") passes format-level validation, even though
// /etc/passwd is typically a system-managed file no peipkg owns. The
// install-time consumer is responsible for catching this via collision
// detection. See the §3.4 informative note covering this case.
func TestValidateAcceptsSymlinkToSystemFileShape(t *testing.T) {
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/share/foo/link", kind: leafSymlink, linkTarget: "../../../etc/passwd"},
	})
	if err != nil {
		t.Errorf("format-level validator should accept syntactically valid /etc/-relative target; got: %v", err)
	}
}

func TestValidateRejectsSymlinkOutsidePermittedDest(t *testing.T) {
	// Resolved target lands at "tmp/whatever" — not under §3.4.1.
	pkg := recipe.Package{Name: "p", Architecture: "x86_64"}
	err := runValidate(t, pkg, []leaf{
		{path: "usr/share/foo/link", kind: leafSymlink, linkTarget: "../../../tmp/whatever"},
	})
	if err == nil {
		t.Errorf("expected rejection of out-of-tree resolution, got nil")
	}
}

func TestValidateAggregatesErrors(t *testing.T) {
	// Two distinct violations should both appear in the error message,
	// so a recipe author can fix everything in one pass.
	pkg := recipe.Package{Name: "p", Architecture: "noarch"}
	err := runValidate(t, pkg, []leaf{
		{path: "var/log/foo.log", kind: leafFile},
		{path: "usr/lib/x86_64-linux-peios/libfoo.so", kind: leafFile},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "/var/") {
		t.Errorf("aggregate error missing /var/ violation:\n%s", msg)
	}
	if !strings.Contains(msg, "noarch") {
		t.Errorf("aggregate error missing noarch violation:\n%s", msg)
	}
}

func TestConvertDepsSortedByName(t *testing.T) {
	cfg := Config{Version: "1.0-1"}
	deps, err := convertDeps([]recipe.Dependency{
		{Name: "libz"},
		{Name: "libc"},
		{Name: "libssl"},
	}, cfg, "pkg", "dependencies")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"libc", "libssl", "libz"}
	for i, d := range deps {
		if d.Name != want[i] {
			t.Errorf("deps[%d].Name = %q, want %q", i, d.Name, want[i])
		}
	}
}
