package pack_test

import (
	"archive/tar"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg-build/internal/manifest"
	"github.com/peios/peipkg-build/internal/pack"
	"github.com/peios/peipkg-build/internal/signature"
)

// projectRoot points at the peipkg-build repo root.
func projectRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func helloNoarchStaged(t *testing.T) string {
	return filepath.Join(projectRoot(t), "testdata", "cases", "hello-noarch", "staged")
}

func helloNoarchManifest() manifest.Manifest {
	return manifest.Manifest{
		Name:         "hello",
		Version:      "0.1-1",
		Architecture: "noarch",
		Description:  "Smallest legal peipkg test fixture.",
		License:      "CC0-1.0",
		Homepage:     "https://peios.org",
		Build: manifest.Build{
			Timestamp: "2026-05-06T12:00:00Z",
			FarmID:    "test-farm-1",
			SourceRef: "test://hello-noarch",
		},
	}
}

func packHelloNoarch(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pack.Pack(pack.Input{
		StagedRoot: helloNoarchStaged(t),
		Manifest:   helloNoarchManifest(),
		Out:        &buf,
	}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	return buf.Bytes()
}

// TestPackDeterministic verifies that two invocations with identical inputs
// produce byte-identical output. This is the core reproducibility guarantee
// of PSD-009 §3.1.4.
func TestPackDeterministic(t *testing.T) {
	a := packHelloNoarch(t)
	b := packHelloNoarch(t)
	if !bytes.Equal(a, b) {
		t.Fatalf("pack output not deterministic: %d bytes vs %d bytes; first diff at %d",
			len(a), len(b), firstDiff(a, b))
	}
}

func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := range n {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestPackVerifyScript runs scripts/verify.sh against the packed output.
// verify.sh is the spec-conformant validator: passing it implies every
// §3.1.4 / §3.2 / §3.3 / §3.5 invariant the validator covers is upheld.
func TestPackVerifyScript(t *testing.T) {
	for _, bin := range []string{"bash", "zstd", "python3"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("verify.sh requires %s, not found in PATH", bin)
		}
	}

	out := filepath.Join(t.TempDir(), "hello.peipkg")
	if err := os.WriteFile(out, packHelloNoarch(t), 0o644); err != nil {
		t.Fatal(err)
	}

	verify := filepath.Join(projectRoot(t), "scripts", "verify.sh")
	cmd := exec.Command("bash", verify, out)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify.sh failed: %v\noutput:\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("PASS")) {
		t.Errorf("verify.sh did not report PASS:\n%s", output)
	}
}

// TestPackNoPAXRecords checks that no PAX extended or global headers appear
// in the output, given that no payload path in hello-noarch exceeds the
// ustar 100-byte limit (§3.1.4 #11/#12). archive/tar in FormatPAX mode
// emits a PAX record whenever a Header field is too large to fit ustar; we
// must keep the whole archive within ustar limits to suppress those records.
//
// archive/tar's reader silently consumes PAX records when decoding, so we
// scan the raw decompressed blocks rather than going through tar.Reader.
func TestPackNoPAXRecords(t *testing.T) {
	compressed := packHelloNoarch(t)

	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%512 != 0 {
		t.Fatalf("decompressed size %d not a multiple of 512", len(raw))
	}

	contentBlocks := 0
	for i := 0; i < len(raw); i += 512 {
		if contentBlocks > 0 {
			contentBlocks--
			continue
		}
		block := raw[i : i+512]
		if isAllZeros(block) {
			continue
		}

		typeflag := block[156]
		switch typeflag {
		case 'g':
			t.Errorf("PAX global header (typeflag 'g') at offset %d (PSD-009 §3.1.4 #11 forbids them)", i)
		case 'x':
			name := strings.TrimRight(string(block[0:100]), "\x00")
			t.Errorf("PAX extended header (typeflag 'x') for %q at offset %d (no path > 100 bytes in hello-noarch, so §3.1.4 #12 forbids the record)",
				name, i)
		}

		size := readOctal(block[124:136])
		contentBlocks = int((size + 511) / 512)
	}
}

func isAllZeros(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// readOctal parses a fixed-width octal field of the kind tar uses for size,
// uid, gid, mode, mtime. Trailing space/NUL padding is tolerated.
func readOctal(field []byte) int64 {
	s := strings.TrimRight(string(field), "\x00 ")
	if s == "" {
		return 0
	}
	var v int64
	if _, err := fmt.Sscanf(s, "%o", &v); err != nil {
		return 0
	}
	return v
}

// loadTestSigningKey returns the committed test private key.
func loadTestSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	path := filepath.Join(projectRoot(t), "testdata", "keys", "test-signing.ed25519")
	priv, err := signature.LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func packHelloNoarchSigned(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := pack.Pack(pack.Input{
		StagedRoot: helloNoarchStaged(t),
		Manifest:   helloNoarchManifest(),
		SignKey:    priv,
		Out:        &buf,
	}); err != nil {
		t.Fatalf("pack: %v", err)
	}
	return buf.Bytes()
}

// TestPackSignedDeterministic verifies signing preserves byte-determinism:
// same key + same input produce the same .peipkg bytes. Ed25519 signatures
// are deterministic per RFC 8032 §5.1.6, and our hashing pipeline is
// deterministic by construction, so the property must hold.
func TestPackSignedDeterministic(t *testing.T) {
	priv := loadTestSigningKey(t)
	a := packHelloNoarchSigned(t, priv)
	b := packHelloNoarchSigned(t, priv)
	if !bytes.Equal(a, b) {
		t.Fatalf("signed pack output not deterministic: %d vs %d bytes; first diff at %d",
			len(a), len(b), firstDiff(a, b))
	}
}

// TestPackSignedHasSignatureEntry verifies the signature entry is the
// last entry in the archive (§3.2.3 archive order).
func TestPackSignedHasSignatureEntry(t *testing.T) {
	priv := loadTestSigningKey(t)
	compressed := packHelloNoarchSigned(t, priv)

	entries := decompressEntryNames(t, compressed)
	if len(entries) == 0 {
		t.Fatal("no entries in archive")
	}
	last := entries[len(entries)-1]
	if last != signature.EntryPath {
		t.Errorf("last entry = %q, want %q", last, signature.EntryPath)
	}
}

// TestPackSignedEnvelopeShape verifies the signature entry's content
// matches the §5.1.3 envelope schema.
func TestPackSignedEnvelopeShape(t *testing.T) {
	priv := loadTestSigningKey(t)
	compressed := packHelloNoarchSigned(t, priv)

	envBytes := extractEntry(t, compressed, signature.EntryPath)

	if !bytes.HasSuffix(envBytes, []byte("\n")) {
		t.Error("signature envelope missing trailing newline")
	}

	// Strict-parse: only the four fields the spec defines.
	var env signature.Envelope
	if err := json.Unmarshal(envBytes, &env); err != nil {
		t.Fatalf("envelope parse: %v", err)
	}
	if env.SchemaVersion != signature.SchemaVersion {
		t.Errorf("schema_version = %d, want %d", env.SchemaVersion, signature.SchemaVersion)
	}
	if env.Algorithm != signature.Algorithm {
		t.Errorf("algorithm = %q, want %q", env.Algorithm, signature.Algorithm)
	}
	if want := signature.Fingerprint(priv.Public().(ed25519.PublicKey)); env.KeyFingerprint != want {
		t.Errorf("key_fingerprint = %q, want %q", env.KeyFingerprint, want)
	}
}

// TestPackSignatureVerifies is the cryptographic-correctness test: extract
// the signature, recompute the SHA-256 over the pre-signature tar bytes,
// and confirm the signature verifies. If this passes, peipkg-build is
// signing the right bytes.
func TestPackSignatureVerifies(t *testing.T) {
	priv := loadTestSigningKey(t)
	pub := priv.Public().(ed25519.PublicKey)

	compressed := packHelloNoarchSigned(t, priv)
	rawTar := decompress(t, compressed)

	sigOffset, sigEnvelope := findSignatureEntry(t, rawTar)
	preSignature := rawTar[:sigOffset]
	digest := sha256.Sum256(preSignature)

	sigBytes, err := base64.RawStdEncoding.DecodeString(sigEnvelope.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, digest[:], sigBytes) {
		t.Errorf("signature does not verify against pre-signature tar bytes (signed digest: %x)", digest)
	}
}

// decompressEntryNames returns the path of every tar entry in archive order.
func decompressEntryNames(t *testing.T, compressed []byte) []string {
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

func extractEntry(t *testing.T, compressed []byte, name string) []byte {
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
		if h.Name == name {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatalf("entry %q not found in archive", name)
	return nil
}

func decompress(t *testing.T, compressed []byte) []byte {
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

// findSignatureEntry scans raw tar bytes for the .peipkg/signature header,
// returning the byte offset of that header and the parsed envelope. The
// pre-signature tar bytes are rawTar[:offset] and that's what the
// signature signs (§5.1.2).
func findSignatureEntry(t *testing.T, rawTar []byte) (int, signature.Envelope) {
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
	t.Fatal("signature entry not found in archive")
	return 0, signature.Envelope{}
}

// TestPackTrailingZeroBlocks verifies the archive ends with exactly two
// zero blocks (1024 bytes), the canonical tar end-of-archive marker, with
// no blocking-factor padding (§3.1.4: the format mandates no extra padding).
func TestPackTrailingZeroBlocks(t *testing.T) {
	compressed := packHelloNoarch(t)

	zr, err := zstd.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}

	if len(raw) < 1024 {
		t.Fatalf("archive too small (%d bytes) to contain trailer", len(raw))
	}

	tail := raw[len(raw)-1024:]
	if !isAllZeros(tail) {
		t.Errorf("last 1024 bytes are not the canonical zero-block trailer")
	}

	// Beyond the trailer there should be no extra zero padding: the block
	// before the trailer must NOT be all zeros (it should be the last
	// payload block or padding within the last entry's content).
	if len(raw) >= 1536 {
		preTrailer := raw[len(raw)-1536 : len(raw)-1024]
		if isAllZeros(preTrailer) {
			t.Errorf("found extra zero block before the 2-block trailer (blocking-factor padding leaked through)")
		}
	}
}
