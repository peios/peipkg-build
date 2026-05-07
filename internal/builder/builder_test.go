package builder_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg-build/internal/builder"
	"github.com/peios/peipkg-build/internal/manifest"
	"github.com/peios/peipkg-build/internal/recipe"
	"github.com/peios/peipkg-build/internal/signature"
)

func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// TestBuildHelloNoarch exercises the full recipe → .peipkg pipeline against
// the hello-noarch fixture. Success criteria: exactly one .peipkg with the
// expected filename, byte-deterministic across two runs, and passing
// scripts/verify.sh.
func TestBuildHelloNoarch(t *testing.T) {
	root := projectRoot(t)
	caseDir := filepath.Join(root, "testdata", "cases", "hello-noarch")
	recipePath := filepath.Join(caseDir, "recipe", "peipkg.toml")
	stagedDir := filepath.Join(caseDir, "staged")

	r, err := recipe.Load(recipePath)
	if err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(filepath.Dir(recipePath), r.Meta.BuildScript)

	runOnce := func(outDir string) []byte {
		cfg := builder.Config{
			Recipe:      r,
			BuildScript: buildScript,
			SourceDir:   stagedDir, // hello-noarch's build.sh just copies the staged tree
			Version:     "0.1-1",
			SourceRef:   "test://hello-noarch",
			FarmID:      "test-farm-1",
			Timestamp:   "2026-05-06T12:00:00Z",
			OutDir:      outDir,
			Stdout:      io.Discard,
			Stderr:      io.Discard,
		}
		res, err := builder.Build(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(res.Outputs) != 1 {
			t.Fatalf("got %d outputs, want 1", len(res.Outputs))
		}
		want := filepath.Join(outDir, "hello_0.1-1_noarch.peipkg")
		if res.Outputs[0] != want {
			t.Errorf("output path = %q, want %q", res.Outputs[0], want)
		}
		bytes, err := os.ReadFile(res.Outputs[0])
		if err != nil {
			t.Fatal(err)
		}
		return bytes
	}

	a := runOnce(t.TempDir())
	b := runOnce(t.TempDir())
	if !bytes.Equal(a, b) {
		t.Errorf("build output not deterministic across runs: %d vs %d bytes", len(a), len(b))
	}

	// Run verify.sh against the output if its dependencies are available.
	for _, bin := range []string{"bash", "zstd", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("verify.sh requires %s (not in PATH); skipping spec-conformance check", bin)
		}
	}
	out := filepath.Join(t.TempDir(), "verified.peipkg")
	if err := os.WriteFile(out, a, 0o644); err != nil {
		t.Fatal(err)
	}
	verify := filepath.Join(root, "scripts", "verify.sh")
	cmd := exec.Command("bash", verify, out)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("PASS")) {
		t.Errorf("verify.sh did not PASS:\n%s", output)
	}
}

// TestBuildHelloX8664Signed exercises the full pipeline against the
// hello-x86_64 fixture: triplet path, in-tree symlink, ldconfig side
// effect, and Ed25519 signing. Success criteria: deterministic byte-equal
// output across two runs, verify.sh PASS, signature envelope matches the
// committed test key, and the cryptographic signature verifies against
// the recomputed digest of the pre-signature tar bytes.
func TestBuildHelloX8664Signed(t *testing.T) {
	root := projectRoot(t)
	caseDir := filepath.Join(root, "testdata", "cases", "hello-x86_64")
	recipePath := filepath.Join(caseDir, "recipe", "peipkg.toml")
	stagedDir := filepath.Join(caseDir, "staged")
	keyPath := filepath.Join(root, "testdata", "keys", "test-signing.ed25519")

	r, err := recipe.Load(recipePath)
	if err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(filepath.Dir(recipePath), r.Meta.BuildScript)

	priv, err := signature.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	runOnce := func(outDir string) []byte {
		cfg := builder.Config{
			Recipe:      r,
			BuildScript: buildScript,
			SourceDir:   stagedDir,
			Version:     "1.2.3-1",
			SourceRef:   "test://hello-x86_64",
			FarmID:      "test-farm-1",
			Timestamp:   "2026-05-06T12:00:00Z",
			OutDir:      outDir,
			SignKey:     priv,
			Stdout:      io.Discard,
			Stderr:      io.Discard,
		}
		res, err := builder.Build(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		if len(res.Outputs) != 1 {
			t.Fatalf("got %d outputs, want 1", len(res.Outputs))
		}
		want := filepath.Join(outDir, "hello_1.2.3-1_x86_64.peipkg")
		if res.Outputs[0] != want {
			t.Errorf("output path = %q, want %q", res.Outputs[0], want)
		}
		bs, err := os.ReadFile(res.Outputs[0])
		if err != nil {
			t.Fatal(err)
		}
		return bs
	}

	a := runOnce(t.TempDir())
	b := runOnce(t.TempDir())
	if !bytes.Equal(a, b) {
		t.Errorf("signed build not deterministic across runs: %d vs %d bytes", len(a), len(b))
	}

	// Recover the signature and verify it cryptographically against the
	// recomputed digest of the pre-signature tar bytes. This is the
	// end-to-end correctness check: if it fails, peipkg-build is signing
	// the wrong bytes or with the wrong key.
	rawTar := decompressBytes(t, a)
	sigOffset, env := findSignatureEntryRaw(t, rawTar)

	if env.KeyFingerprint != signature.Fingerprint(pub) {
		t.Errorf("signature key_fingerprint = %q, want %q",
			env.KeyFingerprint, signature.Fingerprint(pub))
	}

	digest := sha256.Sum256(rawTar[:sigOffset])
	sigRaw, err := base64.RawStdEncoding.DecodeString(env.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, digest[:], sigRaw) {
		t.Error("signature does not verify against recomputed pre-signature digest")
	}

	// Spec-conformance: verify.sh must accept the signed package.
	for _, bin := range []string{"bash", "zstd", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("verify.sh requires %s; skipping spec-conformance check", bin)
		}
	}
	out := filepath.Join(t.TempDir(), "verified.peipkg")
	if err := os.WriteFile(out, a, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "verify.sh"), out)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("PASS")) {
		t.Errorf("verify.sh did not PASS:\n%s", output)
	}

	// Tar-level invariants: in-tree symlink resolves correctly, triplet
	// paths are present, and the signature is the final entry.
	names := tarEntryNames(t, a)
	wantPresence := []string{
		".peipkg/manifest.json",
		".peipkg/files.json",
		"usr/lib/x86_64-linux-peios/libhello.so.1",
		"usr/lib/x86_64-linux-peios/libhello.so.1.2.3",
		signature.EntryPath,
	}
	for _, n := range wantPresence {
		if !slices.Contains(names, n) {
			t.Errorf("expected entry %q in archive; got: %v", n, names)
		}
	}
	if names[len(names)-1] != signature.EntryPath {
		t.Errorf("signature must be last entry; got %q", names[len(names)-1])
	}
}

// TestBuildLibfooMultipackage exercises the full pipeline against the
// three-stanza libfoo fixture. Success criteria:
//
//   - Three .peipkg files emitted in [[package]] declaration order.
//   - Partitioning sends the SONAME chain (libfoo.so.1, libfoo.so.1.2.3)
//     to the runtime stanza; the developer link (libfoo.so) plus headers,
//     static lib, and pkgconfig to -dev; man pages to -doc.
//   - The cross-package symlink (libfoo.so → libfoo.so.1) lands in -dev,
//     and validation accepts it because libfoo.so.1 resolves under §3.4.1.
//   - same_build = true on -dev's libfoo dep resolves to "= <version>".
//   - Dependencies sort lex within the field (§4.1).
//   - All three packages pass verify.sh; all three signatures verify
//     cryptographically against the test public key.
//   - Determinism holds across runs.
func TestBuildLibfooMultipackage(t *testing.T) {
	root := projectRoot(t)
	caseDir := filepath.Join(root, "testdata", "cases", "libfoo-multipackage")
	recipePath := filepath.Join(caseDir, "recipe", "peipkg.toml")
	stagedDir := filepath.Join(caseDir, "staged")
	keyPath := filepath.Join(root, "testdata", "keys", "test-signing.ed25519")

	r, err := recipe.Load(recipePath)
	if err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(filepath.Dir(recipePath), r.Meta.BuildScript)

	priv, err := signature.LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	const version = "1.0.0-1"

	runOnce := func() (outDir string, outputs []string) {
		outDir = t.TempDir()
		cfg := builder.Config{
			Recipe:      r,
			BuildScript: buildScript,
			SourceDir:   stagedDir,
			Version:     version,
			SourceRef:   "test://libfoo-multipackage",
			FarmID:      "test-farm-1",
			Timestamp:   "2026-05-06T12:00:00Z",
			OutDir:      outDir,
			SignKey:     priv,
			Stdout:      io.Discard,
			Stderr:      io.Discard,
		}
		res, err := builder.Build(context.Background(), cfg)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		return outDir, res.Outputs
	}

	outDirA, outputsA := runOnce()
	outDirB, outputsB := runOnce()

	// Determinism: each pair of outputs (same package across two runs)
	// must be byte-identical.
	if len(outputsA) != 3 || len(outputsB) != 3 {
		t.Fatalf("expected 3 outputs per run, got %d / %d", len(outputsA), len(outputsB))
	}
	for i := range outputsA {
		a := mustRead(t, outputsA[i])
		b := mustRead(t, outputsB[i])
		if !bytes.Equal(a, b) {
			t.Errorf("output %d not deterministic: %d vs %d bytes",
				i, len(a), len(b))
		}
	}
	_ = outDirA
	_ = outDirB

	// Filenames must follow <name>_<version>_<arch>.peipkg.
	wantNames := map[string]string{
		"libfoo":     "libfoo_" + version + "_x86_64.peipkg",
		"libfoo-dev": "libfoo-dev_" + version + "_x86_64.peipkg",
		"libfoo-doc": "libfoo-doc_" + version + "_noarch.peipkg",
	}
	got := map[string]string{} // name -> output path
	for _, p := range outputsA {
		base := filepath.Base(p)
		for n, want := range wantNames {
			if base == want {
				got[n] = p
			}
		}
	}
	for n := range wantNames {
		if _, ok := got[n]; !ok {
			t.Errorf("no output found for package %q (looking for %q)", n, wantNames[n])
		}
	}

	// Partition assertions: the right paths land in the right packages.
	expectPayload := map[string][]string{
		"libfoo": {
			"usr/lib/x86_64-linux-peios/libfoo.so.1",
			"usr/lib/x86_64-linux-peios/libfoo.so.1.2.3",
		},
		"libfoo-dev": {
			"usr/include/foo.h",
			"usr/lib/x86_64-linux-peios/libfoo.a",
			"usr/lib/x86_64-linux-peios/libfoo.so",
			"usr/lib/x86_64-linux-peios/pkgconfig/foo.pc",
		},
		"libfoo-doc": {
			"usr/share/man/man3/foo.3",
		},
	}
	for name, want := range expectPayload {
		got := payloadEntries(t, mustRead(t, got[name]))
		for _, p := range want {
			if !slices.Contains(got, p) {
				t.Errorf("package %s: missing expected payload entry %q (got: %v)", name, p, got)
			}
		}
	}

	// same_build resolution: libfoo-dev's libfoo dep must carry the
	// concrete version constraint, and deps must be sorted by name.
	devManifest := readManifest(t, mustRead(t, got["libfoo-dev"]))
	if len(devManifest.Dependencies) != 2 {
		t.Fatalf("libfoo-dev: %d deps, want 2", len(devManifest.Dependencies))
	}
	if devManifest.Dependencies[0].Name != "libc-dev" {
		t.Errorf("libfoo-dev deps not sorted: first dep is %q, want libc-dev",
			devManifest.Dependencies[0].Name)
	}
	libfooDep := devManifest.Dependencies[1]
	if libfooDep.Name != "libfoo" {
		t.Errorf("libfoo-dev deps[1].Name = %q, want libfoo", libfooDep.Name)
	}
	if libfooDep.Constraint != "= "+version {
		t.Errorf("libfoo-dev libfoo dep constraint = %q, want %q",
			libfooDep.Constraint, "= "+version)
	}

	// noarch coherence: libfoo-doc's payload contains nothing under
	// /usr/lib/<triplet>/ — that would have been rejected by the
	// validator. Guard explicitly so a future fixture change can't slip.
	docPayload := payloadEntries(t, mustRead(t, got["libfoo-doc"]))
	for _, p := range docPayload {
		if strings.Contains(p, "x86_64-linux-peios") {
			t.Errorf("libfoo-doc (noarch) contains arch-specific path %q", p)
		}
	}

	// Cryptographic verification: every output's signature verifies
	// against the test public key.
	for name, path := range got {
		bs := mustRead(t, path)
		rawTar := decompressBytes(t, bs)
		sigOffset, env := findSignatureEntryRaw(t, rawTar)

		if env.KeyFingerprint != signature.Fingerprint(pub) {
			t.Errorf("%s: key_fingerprint = %q, want %q",
				name, env.KeyFingerprint, signature.Fingerprint(pub))
		}
		digest := sha256.Sum256(rawTar[:sigOffset])
		sigRaw, err := base64.RawStdEncoding.DecodeString(env.Signature)
		if err != nil {
			t.Errorf("%s: decode signature: %v", name, err)
			continue
		}
		if !ed25519.Verify(pub, digest[:], sigRaw) {
			t.Errorf("%s: signature does not verify", name)
		}
	}

	// Spec conformance via verify.sh on each output.
	for _, bin := range []string{"bash", "zstd", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("verify.sh requires %s; skipping spec-conformance check", bin)
		}
	}
	verify := filepath.Join(root, "scripts", "verify.sh")
	for name, path := range got {
		cmd := exec.Command("bash", verify, path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: verify.sh failed: %v\n%s", name, err, output)
		}
		if !bytes.Contains(output, []byte("PASS")) {
			t.Errorf("%s: verify.sh did not PASS:\n%s", name, output)
		}
	}
}

// mustRead returns the contents of path or fails the test.
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	bs, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

// payloadEntries returns the payload-side tar entry names from a .peipkg,
// excluding metadata under .peipkg/ and directory entries (which are
// synthesized from claimed paths and not the partition's concern).
func payloadEntries(t *testing.T, compressed []byte) []string {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var out []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(h.Name, ".peipkg/") {
			continue
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		// archive/tar reports tar dir entries with TypeDir but our writer
		// also appends a trailing slash; filter those that slip through.
		if strings.HasSuffix(h.Name, "/") {
			continue
		}
		out = append(out, h.Name)
	}
	return out
}

// readManifest extracts and parses the .peipkg/manifest.json from a
// signed or unsigned .peipkg.
func readManifest(t *testing.T, compressed []byte) manifest.Manifest {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Name == ".peipkg/manifest.json" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			var m manifest.Manifest
			if err := json.Unmarshal(body, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	t.Fatal("manifest.json not found")
	return manifest.Manifest{}
}

func decompressBytes(t *testing.T, compressed []byte) []byte {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func tarEntryNames(t *testing.T, compressed []byte) []string {
	t.Helper()
	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	return names
}

// findSignatureEntryRaw scans raw tar bytes for the .peipkg/signature
// header. Returns the byte offset of the header and the parsed envelope.
// The pre-signature tar bytes are rawTar[:offset].
func findSignatureEntryRaw(t *testing.T, rawTar []byte) (int, signature.Envelope) {
	t.Helper()
	contentBlocks := 0
	for i := 0; i < len(rawTar); i += 512 {
		if contentBlocks > 0 {
			contentBlocks--
			continue
		}
		block := rawTar[i : i+512]
		if isAllZeros(block) {
			break
		}
		name := strings.TrimRight(string(block[0:100]), "\x00")
		size := readOctal(block[124:136])
		if name == signature.EntryPath {
			body := rawTar[i+512 : i+512+int(size)]
			var env signature.Envelope
			if err := json.Unmarshal(body, &env); err != nil {
				t.Fatalf("parse signature envelope: %v", err)
			}
			return i, env
		}
		contentBlocks = int((size + 511) / 512)
	}
	t.Fatal("signature entry not found")
	return 0, signature.Envelope{}
}

func isAllZeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func readOctal(field []byte) int64 {
	s := strings.TrimRight(string(field), "\x00 ")
	if s == "" {
		return 0
	}
	var v int64
	for _, c := range s {
		if c < '0' || c > '7' {
			return v
		}
		v = v*8 + int64(c-'0')
	}
	return v
}
