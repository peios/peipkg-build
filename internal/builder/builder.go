// Package builder orchestrates a recipe-driven build: it runs the build
// script into a sandboxed staging directory, partitions the result across
// the recipe's [[package]] stanzas, and emits one .peipkg per stanza by
// calling internal/pack.
//
// Builder owns three concerns that pack does not:
//
//   - Process execution. It runs build.sh in a clean environment with the
//     spec'd variable set (DESIGN.md "CLI" section).
//   - File partitioning. Doublestar globs declared by each stanza are
//     matched against the staged tree; orphan paths and stanza overlap are
//     hard errors.
//   - Recipe-to-manifest conversion. Recipe-level conveniences (most
//     notably the same_build dependency shorthand) are resolved into the
//     normative manifest schema before pack ever sees them.
package builder

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/peios/peipkg-build/internal/binsign"
	"github.com/peios/peipkg-build/internal/manifest"
	"github.com/peios/peipkg-build/internal/pack"
	"github.com/peios/peipkg-build/internal/recipe"
)

// Config holds everything needed for one build invocation. Every field is
// required unless documented otherwise.
type Config struct {
	// Recipe is the parsed peipkg.toml.
	Recipe recipe.Recipe

	// BuildScript is the absolute path to the script named by
	// Recipe.Meta.BuildScript. Resolution happens at the CLI layer; builder
	// does not interpret recipe-relative paths.
	BuildScript string

	// SourceDir is the absolute path to the source checkout passed to
	// build.sh as $SOURCE_DIR.
	SourceDir string

	// Build provenance, all supplied by the build farm.
	Version   string
	SourceRef string
	FarmID    string
	Timestamp string // RFC 3339 UTC, MUST end with 'Z'

	// OutDir is the directory into which one .peipkg is written per
	// [[package]] stanza. It is created if it does not exist.
	OutDir string

	// SignKey is the Ed25519 private key used to sign emitted .peipkg
	// files. Zero-value means unsigned (still spec-conformant per §5.1.7).
	// All packages produced by one Build invocation are signed with this
	// single key.
	SignKey ed25519.PrivateKey

	// BuildEnv is a set of declared NAME=VALUE pairs injected into the build
	// script's environment on top of the hermetic base. It is how the farm
	// passes build inputs it holds out-of-band — e.g. PKM_KACS_TCB_PUBKEY_HEX
	// for the kernel's signing-key catalogue. Names that collide with the
	// reserved hermetic variables, or are not valid shell identifiers, are
	// rejected. These are *declared* inputs, not host-environment leakage, so
	// reproducibility is preserved.
	BuildEnv map[string]string

	// BinarySigners maps a signing-key name (as referenced by a recipe
	// [[sign]] stanza's `key`) to the Signer that embeds a .peios.sig
	// signature into the staged output. The farm supplies only the keys a
	// recipe is authorized to use; a [[sign]] referencing an absent key is a
	// hard error. Signing runs after the build script (so it is the last
	// mutation of the binary) and before partition/pack.
	BinarySigners map[string]binsign.Signer

	// Stdout and Stderr receive build.sh output. Nil falls back to the
	// process's os.Stdout / os.Stderr.
	Stdout io.Writer
	Stderr io.Writer
}

// Result reports what Build produced.
type Result struct {
	// Outputs is the set of absolute paths to the emitted .peipkg files,
	// in [[package]] declaration order.
	Outputs []string
}

// Build runs the recipe end-to-end. It returns once every [[package]] stanza
// has been packed or the first error has occurred. Partial outputs from a
// failed run are removed; successfully-packed siblings before the failure
// are preserved.
func Build(ctx context.Context, cfg Config) (Result, error) {
	if err := cfg.validate(); err != nil {
		return Result{}, err
	}

	epoch, err := timestampToEpoch(cfg.Timestamp)
	if err != nil {
		return Result{}, fmt.Errorf("parse timestamp: %w", err)
	}

	sourceAbs, err := filepath.Abs(cfg.SourceDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve source dir: %w", err)
	}
	outAbs, err := filepath.Abs(cfg.OutDir)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output dir: %w", err)
	}
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return Result{}, fmt.Errorf("create output dir: %w", err)
	}

	// Staging area: one parent temp directory containing the destdir (where
	// build.sh installs) and a separate workdir (where build.sh runs from,
	// for out-of-tree build patterns). Removed unconditionally on return.
	stage, err := os.MkdirTemp("", "peipkg-build-")
	if err != nil {
		return Result{}, fmt.Errorf("create staging area: %w", err)
	}
	defer os.RemoveAll(stage)

	destDir := filepath.Join(stage, "destdir")
	workDir := filepath.Join(stage, "work")
	for _, d := range []string{destDir, workDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return Result{}, fmt.Errorf("create %s: %w", d, err)
		}
	}

	if err := runBuildScript(ctx, cfg, sourceAbs, destDir, workDir, epoch); err != nil {
		return Result{}, fmt.Errorf("run build script: %w", err)
	}

	if err := signBinaries(cfg, destDir); err != nil {
		return Result{}, err
	}

	leaves, err := collectLeaves(destDir, cfg.Recipe.Packages)
	if err != nil {
		return Result{}, fmt.Errorf("walk staged tree: %w", err)
	}

	claims, err := partitionLeaves(leaves, cfg.Recipe.Packages)
	if err != nil {
		return Result{}, err
	}

	if err := validateClaims(cfg.Recipe.Packages, claims, leaves); err != nil {
		return Result{}, err
	}

	outputs := make([]string, 0, len(cfg.Recipe.Packages))
	for _, pkg := range cfg.Recipe.Packages {
		outPath, err := emitPackage(cfg, pkg, destDir, claims[pkg.Name], outAbs)
		if err != nil {
			return Result{Outputs: outputs}, fmt.Errorf("package %s: %w", pkg.Name, err)
		}
		outputs = append(outputs, outPath)
	}

	return Result{Outputs: outputs}, nil
}

func (cfg *Config) validate() error {
	switch {
	case cfg.BuildScript == "":
		return fmt.Errorf("BuildScript is required")
	case cfg.SourceDir == "":
		return fmt.Errorf("SourceDir is required")
	case cfg.Version == "":
		return fmt.Errorf("Version is required")
	case cfg.SourceRef == "":
		return fmt.Errorf("SourceRef is required")
	case cfg.FarmID == "":
		return fmt.Errorf("FarmID is required")
	case cfg.Timestamp == "":
		return fmt.Errorf("Timestamp is required")
	case cfg.OutDir == "":
		return fmt.Errorf("OutDir is required")
	}
	if err := cfg.Recipe.Validate(); err != nil {
		return fmt.Errorf("recipe: %w", err)
	}
	return nil
}

// timestampToEpoch parses an RFC 3339 instant and returns its UNIX seconds.
// The spec (§3.3.4) mandates the 'Z' UTC designator; an offset like
// +00:00 represents the same instant but is rejected here so producers
// emit one canonical timestamp form.
func timestampToEpoch(ts string) (int64, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return 0, err
	}
	if !strings.HasSuffix(ts, "Z") {
		return 0, fmt.Errorf("timestamp must end with 'Z' for UTC (got %q)", ts)
	}
	return t.Unix(), nil
}

// runBuildScript executes the recipe's build script with the environment
// the spec mandates and stdin tied to /dev/null.
//
// Env construction: we replace the inherited environment wholesale rather
// than augmenting it. The spec calls for a "clean environment apart from"
// the listed variables, so leaking host-side variables (HOME, USER, etc.)
// into the build is forbidden. PATH is re-introduced because build scripts
// invariably need it; the farm is responsible for supplying a sane PATH.
func runBuildScript(ctx context.Context, cfg Config, sourceAbs, destDir, workDir string, epoch int64) error {
	if _, err := os.Stat(cfg.BuildScript); err != nil {
		return fmt.Errorf("locate build script: %w", err)
	}

	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	env, err := buildScriptEnv(cfg, sourceAbs, destDir, epoch)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, "sh", cfg.BuildScript)
	cmd.Dir = workDir
	cmd.Env = env
	cmd.Stdin = nil // /dev/null per exec.Cmd docs
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return cmd.Run()
}

// reservedBuildEnv names the hermetic variables runBuildScript controls. A
// caller-supplied BuildEnv entry may not shadow them — that would let a recipe
// (or its farm config) subvert the staging contract.
var reservedBuildEnv = map[string]bool{
	"SOURCE_DIR":        true,
	"DESTDIR":           true,
	"SOURCE_DATE_EPOCH": true,
	"LC_ALL":            true,
	"TZ":                true,
	"PATH":              true,
}

// buildEnvNameRe is the POSIX shell name grammar: a build-env variable name
// must be a valid identifier so `sh` actually exports it.
var buildEnvNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// buildScriptEnv builds the environment for the build script: the hermetic
// base plus any declared BuildEnv entries, emitted in sorted order for
// determinism. Invalid or reserved BuildEnv names are rejected.
func buildScriptEnv(cfg Config, sourceAbs, destDir string, epoch int64) ([]string, error) {
	env := []string{
		"SOURCE_DIR=" + sourceAbs,
		"DESTDIR=" + destDir,
		"SOURCE_DATE_EPOCH=" + strconv.FormatInt(epoch, 10),
		"LC_ALL=C",
		"TZ=UTC",
		"PATH=" + os.Getenv("PATH"),
	}

	names := make([]string, 0, len(cfg.BuildEnv))
	for name := range cfg.BuildEnv {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !buildEnvNameRe.MatchString(name) {
			return nil, fmt.Errorf("build-env: invalid variable name %q", name)
		}
		if reservedBuildEnv[name] {
			return nil, fmt.Errorf("build-env: %q is reserved and cannot be overridden", name)
		}
		env = append(env, name+"="+cfg.BuildEnv[name])
	}
	return env, nil
}

// signBinaries embeds a .peios.sig signature into each [[sign]]-declared staged
// output using the named Signer the farm supplied. It runs after the build
// script (so signing is the binary's last mutation) and before partition/pack
// (so the signed bytes are what ship). A [[sign]] whose key was not supplied,
// or whose path escapes $DESTDIR or is missing/not a regular file, is a hard
// error — silently shipping an unsigned TCB binary is the failure we refuse.
func signBinaries(cfg Config, destDir string) error {
	if len(cfg.Recipe.Sign) == 0 {
		return nil
	}
	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for i, s := range cfg.Recipe.Sign {
		signer, ok := cfg.BinarySigners[s.Key]
		if !ok {
			return fmt.Errorf("sign[%d] %s: no signing key named %q supplied (need --binary-sign-key %s=PATH)", i, s.Path, s.Key, s.Key)
		}
		clean := filepath.Clean(filepath.FromSlash(s.Path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("sign[%d]: path %q escapes $DESTDIR", i, s.Path)
		}
		target := filepath.Join(destAbs, clean)
		info, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("sign[%d]: %s: %w", i, s.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("sign[%d]: %s is not a regular file", i, s.Path)
		}
		if err := binsign.SignELF(target, signer); err != nil {
			return fmt.Errorf("sign %s: %w", s.Path, err)
		}
	}
	return nil
}

// leafKind distinguishes regular files from symlinks at partition time.
// Directories are not "leaves"; their tar entries are synthesized inside
// pack from each stanza's claimed paths.
type leafKind int

const (
	leafFile leafKind = iota
	leafSymlink
	leafDir
)

// leaf is the partition-time representation of one staged entry. linkTarget
// is populated only for symlinks; the validator needs it to check §3.4
// target constraints. It is the raw readlink() result, not a resolved path.
type leaf struct {
	path       string
	kind       leafKind
	linkTarget string
}

// collectLeaves returns every package-claimable path under stagedRoot,
// expressed as slash-separated paths relative to stagedRoot. Regular files and
// symlinks are always claimable. Directories are claimable only when a package
// declares an explicit directory pattern ending in "/", keeping ordinary
// parent directories synthesized by pack rather than assigned as payload.
// Forbidden entry types (devices, FIFOs, hardlinks) cause the build to fail
// rather than being silently dropped — pack would reject them anyway and
// surfacing the error here gives a clearer message.
func collectLeaves(stagedRoot string, packages []recipe.Package) ([]leaf, error) {
	var out []leaf
	err := filepath.WalkDir(stagedRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == stagedRoot {
			return nil
		}
		rel, err := filepath.Rel(stagedRoot, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		switch {
		case d.IsDir():
			claimed, err := explicitDirClaim(rel, packages)
			if err != nil {
				return err
			}
			if claimed {
				out = append(out, leaf{path: rel, kind: leafDir})
			}
			return nil
		case d.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", rel, err)
			}
			out = append(out, leaf{path: rel, kind: leafSymlink, linkTarget: target})
		case d.Type().IsRegular():
			out = append(out, leaf{path: rel, kind: leafFile})
		default:
			return fmt.Errorf("%s: unsupported entry type %v (PSD-009 §3.4 permits regular files, directories, and symlinks only)", rel, d.Type())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func explicitDirClaim(p string, packages []recipe.Package) (bool, error) {
	for _, pkg := range packages {
		for _, pattern := range pkg.Files {
			if !strings.HasSuffix(pattern, "/") {
				continue
			}
			ok, err := matchPackagePattern(pattern, leaf{path: p, kind: leafDir})
			if err != nil {
				return false, fmt.Errorf("package %s: invalid glob %q: %w", pkg.Name, pattern, err)
			}
			if ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// partitionLeaves assigns each leaf to exactly one [[package]] by glob match.
// It returns a map keyed by package name whose values are sets of paths
// claimed by that package.
//
// Two errors short-circuit the build:
//
//   - Orphan path: no package's globs match. The expectation is that every
//     staged file ends up in some package; silent loss of files is a
//     production hazard.
//   - Overlap: more than one package's globs match the same path. The
//     recipe must be amended to make the glob lists disjoint. We do not
//     guess based on declaration order.
func partitionLeaves(leaves []leaf, packages []recipe.Package) (map[string]map[string]bool, error) {
	claims := make(map[string]map[string]bool, len(packages))
	for _, p := range packages {
		claims[p.Name] = make(map[string]bool)
	}

	var orphans []string

	for _, l := range leaves {
		matched, err := matchingPackages(l, packages)
		if err != nil {
			return nil, err
		}
		switch len(matched) {
		case 0:
			orphans = append(orphans, l.path)
		case 1:
			claims[matched[0]][l.path] = true
		default:
			return nil, fmt.Errorf("path %q matches multiple packages %v; package file globs must be disjoint", l.path, matched)
		}
	}

	if len(orphans) > 0 {
		sort.Strings(orphans)
		return nil, fmt.Errorf("staged paths claimed by no package:\n  %s", strings.Join(orphans, "\n  "))
	}
	return claims, nil
}

// matchingPackages returns the names of every package whose Files glob list
// matches path. A pattern parse error fails the whole build.
func matchingPackages(l leaf, packages []recipe.Package) ([]string, error) {
	var matched []string
	for _, p := range packages {
		for _, pattern := range p.Files {
			ok, err := matchPackagePattern(pattern, l)
			if err != nil {
				return nil, fmt.Errorf("package %s: invalid glob %q: %w", p.Name, pattern, err)
			}
			if ok {
				matched = append(matched, p.Name)
				break
			}
		}
	}
	return matched, nil
}

func matchPackagePattern(pattern string, l leaf) (bool, error) {
	if l.kind == leafDir && strings.HasSuffix(pattern, "/") {
		pattern = strings.TrimRight(pattern, "/")
	}
	return doublestar.Match(pattern, l.path)
}

// emitPackage assembles the manifest for one stanza and calls pack to emit
// the corresponding .peipkg. The output filename follows the convention
// <name>_<version>_<arch>.peipkg.
func emitPackage(cfg Config, pkg recipe.Package, destDir string, claimed map[string]bool, outDir string) (string, error) {
	m, err := buildManifest(cfg, pkg)
	if err != nil {
		return "", err
	}

	fname := fmt.Sprintf("%s_%s_%s.peipkg", pkg.Name, cfg.Version, pkg.Architecture)
	outPath := filepath.Join(outDir, fname)

	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create output: %w", err)
	}

	selector := func(p string) bool { return claimed[p] }

	packErr := pack.Pack(pack.Input{
		StagedRoot: destDir,
		Selector:   selector,
		Manifest:   m,
		SignKey:    cfg.SignKey,
		Out:        f,
	})
	closeErr := f.Close()

	if packErr != nil {
		_ = os.Remove(outPath)
		return "", packErr
	}
	if closeErr != nil {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("close output: %w", closeErr)
	}
	return outPath, nil
}

// buildManifest produces the manifest.Manifest for one stanza. It pulls
// shared facts from cfg.Recipe.Meta, fills in the build provenance from cfg,
// and converts recipe-level dependency entries into their on-wire form
// (resolving same_build, sorting by name, deduplicating).
func buildManifest(cfg Config, pkg recipe.Package) (manifest.Manifest, error) {
	deps, err := convertDeps(pkg.Dependencies, cfg, pkg.Name, "dependencies")
	if err != nil {
		return manifest.Manifest{}, err
	}
	optDeps, err := convertDeps(pkg.OptionalDependencies, cfg, pkg.Name, "optional_dependencies")
	if err != nil {
		return manifest.Manifest{}, err
	}
	conflicts, err := convertDeps(pkg.Conflicts, cfg, pkg.Name, "conflicts")
	if err != nil {
		return manifest.Manifest{}, err
	}

	provides := make([]manifest.Provides, 0, len(pkg.Provides))
	seenProv := make(map[string]struct{}, len(pkg.Provides))
	for _, v := range pkg.Provides {
		if _, dup := seenProv[v.Name]; dup {
			return manifest.Manifest{}, fmt.Errorf("%s.provides: duplicate name %q", pkg.Name, v.Name)
		}
		seenProv[v.Name] = struct{}{}
		provides = append(provides, manifest.Provides{Name: v.Name, Version: v.Version})
	}
	sort.Slice(provides, func(i, j int) bool { return provides[i].Name < provides[j].Name })

	replaces := make([]manifest.Replaces, 0, len(pkg.Replaces))
	seenRepl := make(map[string]struct{}, len(pkg.Replaces))
	for _, v := range pkg.Replaces {
		if _, dup := seenRepl[v.Name]; dup {
			return manifest.Manifest{}, fmt.Errorf("%s.replaces: duplicate name %q", pkg.Name, v.Name)
		}
		seenRepl[v.Name] = struct{}{}
		replaces = append(replaces, manifest.Replaces{Name: v.Name, Constraint: v.Constraint})
	}
	sort.Slice(replaces, func(i, j int) bool { return replaces[i].Name < replaces[j].Name })

	sideEffects := append([]string(nil), pkg.SideEffects...)

	return manifest.Manifest{
		SchemaVersion:        manifest.SchemaVersion,
		Name:                 pkg.Name,
		Version:              cfg.Version,
		Architecture:         pkg.Architecture,
		Description:          pkg.Description,
		License:              cfg.Recipe.Meta.License,
		Homepage:             cfg.Recipe.Meta.Homepage,
		Dependencies:         deps,
		OptionalDependencies: optDeps,
		Conflicts:            conflicts,
		Provides:             provides,
		Replaces:             replaces,
		SideEffects:          sideEffects,
		Build: manifest.Build{
			Timestamp: cfg.Timestamp,
			FarmID:    cfg.FarmID,
			SourceRef: cfg.SourceRef,
		},
	}, nil
}

// convertDeps performs three jobs at once: it copies recipe-level dependency
// entries into manifest-level entries, resolves the same_build shorthand,
// and rejects duplicate names within the field. The final slice is sorted
// by name (§4.1).
func convertDeps(in []recipe.Dependency, cfg Config, owner, field string) ([]manifest.Dependency, error) {
	out := make([]manifest.Dependency, 0, len(in))
	seen := make(map[string]struct{}, len(in))

	for _, d := range in {
		if _, dup := seen[d.Name]; dup {
			return nil, fmt.Errorf("%s.%s: duplicate name %q (PSD-009 §4.1 forbids identical names within a field)", owner, field, d.Name)
		}
		seen[d.Name] = struct{}{}

		constraint := d.Constraint
		if d.SameBuild {
			if constraint != "" {
				return nil, fmt.Errorf("%s.%s.%s: same_build conflicts with explicit constraint %q", owner, field, d.Name, constraint)
			}
			if !isSiblingPackage(d.Name, cfg.Recipe.Packages) {
				return nil, fmt.Errorf("%s.%s.%s: same_build set but no sibling [[package]] named %q exists", owner, field, d.Name, d.Name)
			}
			constraint = "= " + cfg.Version
		}

		out = append(out, manifest.Dependency{
			Name:       d.Name,
			Constraint: constraint,
			Arch:       d.Arch,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func isSiblingPackage(name string, packages []recipe.Package) bool {
	for _, p := range packages {
		if p.Name == name {
			return true
		}
	}
	return false
}

// permittedTopLevels enumerates the top-level install destinations PSD-009
// §3.4.1 permits. A leaf path is acceptable if some entry in this list is a
// prefix of the path (with the trailing slash treated as a directory
// separator, so "etc/foo" matches "etc/" but "etcetera" does not).
//
// usr/lib/ admits any first-segment-after-lib name to allow the per-triplet
// dispatch (validateLibPath narrows it to "<arch>-linux-peios/" or rejects).
var permittedTopLevels = []string{
	"usr/bin/",
	"usr/lib/",
	"usr/share/",
	"usr/include/",
	"etc/",
	"var/",
	"opt/",
	"boot/",
	"system/",
}

var permittedDirectoryOnlyRoots = map[string]bool{
	"dev":  true,
	"proc": true,
	"run":  true,
	"sys":  true,
	"tmp":  true,
}

// validateClaims runs format-level checks across the post-partition
// assignment of leaves to packages. Errors here mean the recipe author's
// staged tree contains paths or symlinks that would produce a spec-invalid
// peipkg; we surface them at build time rather than at consumer install.
//
// The validator aggregates failures so a single run reports every problem,
// not just the first one. Recipe authors fix the whole list in one pass.
func validateClaims(packages []recipe.Package, claims map[string]map[string]bool, leaves []leaf) error {
	leafByPath := make(map[string]leaf, len(leaves))
	for _, l := range leaves {
		leafByPath[l.path] = l
	}

	var errs []string
	for _, p := range packages {
		paths := make([]string, 0, len(claims[p.Name]))
		for path := range claims[p.Name] {
			paths = append(paths, path)
		}
		sort.Strings(paths)

		for _, lp := range paths {
			l := leafByPath[lp]
			if e := validateLeafPath(p, l); e != nil {
				errs = append(errs, e.Error())
			}
			if l.kind == leafSymlink {
				if e := validateSymlinkTarget(p, l); e != nil {
					errs = append(errs, e.Error())
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("payload validation failed:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// validateLeafPath verifies a single leaf's path against the format-level
// install-destination rules: §3.4.1 permitted top-levels, §3.4.2 triplet
// coherence, §3.4.4 var-must-be-empty.
func validateLeafPath(p recipe.Package, l leaf) error {
	if l.kind == leafDir {
		if hasPermittedTopLevel(l.path) || permittedDirectoryOnlyRoots[l.path] {
			return nil
		}
		return fmt.Errorf("package %s: directory %s is not under any §3.4.1 permitted top-level destination or permitted runtime mountpoint root", p.Name, l.path)
	}

	if !hasPermittedTopLevel(l.path) {
		return fmt.Errorf("package %s: %s is not under any §3.4.1 permitted top-level destination", p.Name, l.path)
	}

	if strings.HasPrefix(l.path, "var/") {
		return fmt.Errorf("package %s: %s installs populated content under /var/ (§3.4.4 forbids this; only empty directories are permitted under /var/)", p.Name, l.path)
	}

	if strings.HasPrefix(l.path, "usr/lib/") {
		if err := validateLibPath(p, l.path); err != nil {
			return err
		}
	}
	return nil
}

func hasPermittedTopLevel(p string) bool {
	for _, top := range permittedTopLevels {
		if p == strings.TrimSuffix(top, "/") {
			return true
		}
		if strings.HasPrefix(p, top) {
			return true
		}
	}
	return false
}

// validateLibPath enforces §3.4.2: anything under /usr/lib/ must be under
// /usr/lib/<triplet>/, the triplet must be <package-arch>-linux-peios, and
// noarch packages must not have any /usr/lib/<triplet>/ entries at all.
func validateLibPath(p recipe.Package, leafPath string) error {
	rest := strings.TrimPrefix(leafPath, "usr/lib/")
	triplet, _, ok := strings.Cut(rest, "/")
	if !ok {
		return fmt.Errorf("package %s: %s sits directly under /usr/lib/ (§3.4.2 requires /usr/lib/<triplet>/<...>)", p.Name, leafPath)
	}

	if p.Architecture == "noarch" {
		return fmt.Errorf("package %s: noarch package contains arch-specific path %s (§3.4.2 forbids /usr/lib/<triplet>/ entries in noarch packages)", p.Name, leafPath)
	}

	expected := p.Architecture + "-linux-peios"
	if triplet != expected {
		return fmt.Errorf("package %s (architecture=%q): %s uses triplet %q, expected %q (§3.4.2)", p.Name, p.Architecture, leafPath, triplet, expected)
	}
	return nil
}

// validateSymlinkTarget enforces §3.4 symlink target constraints: relative,
// resolves under §3.4.1, and meets the path-validity rules. The resolved
// target may be in another package's payload (the cross-package case);
// peipkg-build does not verify the target's owning package is a declared
// dep — that is a producer SHOULD per §3.4 and is outside what pack-time
// validation can check without a full repository index.
func validateSymlinkTarget(p recipe.Package, l leaf) error {
	if l.linkTarget == "" {
		return fmt.Errorf("package %s: symlink %s has empty target", p.Name, l.path)
	}
	if filepath.IsAbs(l.linkTarget) {
		return fmt.Errorf("package %s: symlink %s -> %s: absolute targets forbidden (§3.4 requires relative)", p.Name, l.path, l.linkTarget)
	}
	if strings.ContainsAny(l.linkTarget, "\x00") || strings.Contains(l.linkTarget, "\\") {
		return fmt.Errorf("package %s: symlink %s -> %q: target contains forbidden bytes (§3.4 path-validity)", p.Name, l.path, l.linkTarget)
	}

	parent := path.Dir(l.path)
	if parent == "." {
		parent = ""
	}
	resolved := path.Join(parent, l.linkTarget)

	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("package %s: symlink %s -> %s: target escapes the peipkg-managed tree (§3.4)", p.Name, l.path, l.linkTarget)
	}
	if !hasPermittedTopLevel(resolved) {
		return fmt.Errorf("package %s: symlink %s -> %s resolves to %q, which is not under a §3.4.1 permitted destination", p.Name, l.path, l.linkTarget, resolved)
	}
	return nil
}
