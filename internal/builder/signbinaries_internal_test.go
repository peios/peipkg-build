package builder

import (
	"crypto/ed25519"
	"crypto/rand"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/peios/peipkg-build/internal/binsign"
	"github.com/peios/peipkg-build/internal/recipe"
)

// buildRealELF compiles a trivial static binary to path, or skips if there is
// no Go toolchain. signBinaries needs a real ELF to sign.
func buildRealELF(t *testing.T, path string) {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain; skipping signBinaries ELF test")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "m.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main(){}\n"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	cmd := exec.Command(goBin, "build", "-o", path, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed (%v); skipping: %s", err, out)
	}
}

func testKeySigner(t *testing.T) binsign.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := binsign.NewKeySigner(priv)
	if err != nil {
		t.Fatalf("NewKeySigner: %v", err)
	}
	return s
}

func TestSignBinariesSignsDeclaredOutput(t *testing.T) {
	dest := t.TempDir()
	rel := "usr/lib/x86_64-linux-peios/tool/tool"
	full := filepath.Join(dest, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	buildRealELF(t, full)

	cfg := Config{
		Recipe:        recipe.Recipe{Sign: []recipe.Sign{{Path: rel, Key: "tcb"}}},
		BinarySigners: map[string]binsign.Signer{"tcb": testKeySigner(t)},
	}
	if err := signBinaries(cfg, dest); err != nil {
		t.Fatalf("signBinaries: %v", err)
	}

	f, err := elf.Open(full)
	if err != nil {
		t.Fatalf("open signed output: %v", err)
	}
	defer f.Close()
	s := f.Section(".peios.sig")
	if s == nil {
		t.Fatal("signed output has no .peios.sig section")
	}
	if s.Size != binsign.BlobLen {
		t.Errorf(".peios.sig size = %d, want %d", s.Size, binsign.BlobLen)
	}
}

func TestSignBinariesMissingKeyIsError(t *testing.T) {
	cfg := Config{Recipe: recipe.Recipe{Sign: []recipe.Sign{{Path: "x", Key: "nope"}}}}
	if err := signBinaries(cfg, t.TempDir()); err == nil {
		t.Fatal("expected error when [[sign]] key not supplied")
	}
}

func TestSignBinariesPathEscapeIsError(t *testing.T) {
	cfg := Config{
		Recipe:        recipe.Recipe{Sign: []recipe.Sign{{Path: "../escape", Key: "tcb"}}},
		BinarySigners: map[string]binsign.Signer{"tcb": testKeySigner(t)},
	}
	if err := signBinaries(cfg, t.TempDir()); err == nil {
		t.Fatal("expected error for path escaping $DESTDIR")
	}
}

func TestSignBinariesMissingFileIsError(t *testing.T) {
	cfg := Config{
		Recipe:        recipe.Recipe{Sign: []recipe.Sign{{Path: "usr/bin/absent", Key: "tcb"}}},
		BinarySigners: map[string]binsign.Signer{"tcb": testKeySigner(t)},
	}
	if err := signBinaries(cfg, t.TempDir()); err == nil {
		t.Fatal("expected error when declared sign path is missing")
	}
}

func TestSignBinariesNoStanzasIsNoop(t *testing.T) {
	if err := signBinaries(Config{}, t.TempDir()); err != nil {
		t.Fatalf("no [[sign]] stanzas should be a no-op: %v", err)
	}
}
