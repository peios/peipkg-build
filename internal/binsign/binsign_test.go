package binsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func testSigner(t *testing.T) (*KeySigner, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	s, err := NewKeySigner(priv)
	if err != nil {
		t.Fatalf("NewKeySigner: %v", err)
	}
	return s, pub
}

// buildMinimalELF assembles a valid little-endian ELF64 with two sections
// (null + .shstrtab) and a nonzero body, enough to exercise the signer.
func buildMinimalELF(t *testing.T) []byte {
	t.Helper()
	body := make([]byte, 96)
	for i := range body {
		body[i] = byte(i + 1) // nonzero pattern
	}
	shstr := append([]byte{0}, append([]byte(".shstrtab"), 0)...) // "\0.shstrtab\0"

	var eh elf.Header64
	copy(eh.Ident[:], elf.ELFMAG)
	eh.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	eh.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	eh.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	eh.Type = uint16(elf.ET_EXEC)
	eh.Machine = uint16(elf.EM_X86_64)
	eh.Version = uint32(elf.EV_CURRENT)
	eh.Ehsize = uint16(binary.Size(elf.Header64{}))
	eh.Shentsize = uint16(binary.Size(elf.Section64{}))
	eh.Shnum = 2
	eh.Shstrndx = 1

	hdrSize := binary.Size(eh)
	bodyOff := hdrSize
	shstrOff := bodyOff + len(body)
	shtOff := shstrOff + len(shstr)
	for shtOff%8 != 0 {
		shtOff++
	}
	eh.Shoff = uint64(shtOff)

	out := make([]byte, shtOff) // header + body + shstr + alignment padding
	var hb bytes.Buffer
	if err := binary.Write(&hb, binary.LittleEndian, &eh); err != nil {
		t.Fatalf("encode header: %v", err)
	}
	copy(out[:hdrSize], hb.Bytes())
	copy(out[bodyOff:], body)
	copy(out[shstrOff:], shstr)

	sec0 := elf.Section64{}
	sec1 := elf.Section64{
		Name:      1,
		Type:      uint32(elf.SHT_STRTAB),
		Off:       uint64(shstrOff),
		Size:      uint64(len(shstr)),
		Addralign: 1,
	}
	var sb bytes.Buffer
	if err := binary.Write(&sb, binary.LittleEndian, &sec0); err != nil {
		t.Fatalf("encode section 0: %v", err)
	}
	if err := binary.Write(&sb, binary.LittleEndian, &sec1); err != nil {
		t.Fatalf("encode section 1: %v", err)
	}
	return append(out, sb.Bytes()...)
}

func TestSignAndSelfVerify(t *testing.T) {
	signer, pub := testSigner(t)
	raw := buildMinimalELF(t)

	signed, err := signBytes(raw, signer)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if err := verifyBytes(signed, pub); err != nil {
		t.Fatalf("verifyBytes on freshly signed ELF: %v", err)
	}

	// The .peios.sig section must be present, PROGBITS, exactly 65 bytes.
	_, sections, strtab, _, err := parseELF(signed)
	if err != nil {
		t.Fatalf("parseELF(signed): %v", err)
	}
	found := false
	for _, s := range sections {
		if cString(strtab, s.Name) != SectionName {
			continue
		}
		found = true
		if s.Type != uint32(elf.SHT_PROGBITS) {
			t.Errorf(".peios.sig type = %d, want SHT_PROGBITS", s.Type)
		}
		if s.Size != BlobLen {
			t.Errorf(".peios.sig size = %d, want %d", s.Size, BlobLen)
		}
		if signed[s.Off] != Version {
			t.Errorf(".peios.sig version byte = %#x, want %#x", signed[s.Off], Version)
		}
	}
	if !found {
		t.Fatal("signed ELF has no .peios.sig section")
	}
}

func TestTamperDetected(t *testing.T) {
	signer, pub := testSigner(t)
	signed, err := signBytes(buildMinimalELF(t), signer)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}

	// Flip a byte in the body (outside the signature section). The kernel-rule
	// hash covers it, so verification must fail.
	tampered := append([]byte(nil), signed...)
	tampered[70] ^= 0xff
	if err := verifyBytes(tampered, pub); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("tampered body: err = %v, want ErrVerifyFailed", err)
	}
}

func TestAlreadySignedRejected(t *testing.T) {
	signer, _ := testSigner(t)
	signed, err := signBytes(buildMinimalELF(t), signer)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	if _, err := signBytes(signed, signer); !errors.Is(err, ErrAlreadySigned) {
		t.Fatalf("double sign: err = %v, want ErrAlreadySigned", err)
	}
}

func TestDeterministic(t *testing.T) {
	signer, _ := testSigner(t)
	raw := buildMinimalELF(t)
	a, err := signBytes(raw, signer)
	if err != nil {
		t.Fatalf("signBytes a: %v", err)
	}
	b, err := signBytes(raw, signer)
	if err != nil {
		t.Fatalf("signBytes b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("signing is not deterministic (Ed25519 + assembly should be byte-identical)")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	signer, _ := testSigner(t)
	signed, err := signBytes(buildMinimalELF(t), signer)
	if err != nil {
		t.Fatalf("signBytes: %v", err)
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifyBytes(signed, otherPub); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("verify with wrong key: err = %v, want ErrVerifyFailed", err)
	}
}

func TestNotELFRejected(t *testing.T) {
	signer, _ := testSigner(t)
	if _, err := signBytes([]byte("not an elf file at all"), signer); !errors.Is(err, ErrNotELF64) {
		t.Fatalf("non-ELF: err = %v, want ErrNotELF64", err)
	}
}

func TestSignELFFilePreservesMode(t *testing.T) {
	signer, pub := testSigner(t)
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, buildMinimalELF(t), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := SignELF(path, signer); err != nil {
		t.Fatalf("SignELF: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755 (executable bit must survive signing)", info.Mode().Perm())
	}
	signed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if err := verifyBytes(signed, pub); err != nil {
		t.Fatalf("verify signed file: %v", err)
	}
}

// TestRealELFRoundTrip signs an actual compiled binary and confirms the stdlib
// ELF reader still parses it and finds the section. Skipped without a Go
// toolchain; the boot test (separate) proves the real kernel accepts it.
func TestRealELFRoundTrip(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain; skipping real-ELF round-trip")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	binPath := filepath.Join(dir, "prog")
	cmd := exec.Command(goBin, "build", "-o", binPath, src)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("go build failed (%v); skipping: %s", err, out)
	}

	signer, pub := testSigner(t)
	if err := SignELF(binPath, signer); err != nil {
		t.Fatalf("SignELF on real binary: %v", err)
	}

	signed, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read signed binary: %v", err)
	}
	if err := verifyBytes(signed, pub); err != nil {
		t.Fatalf("verify signed real binary: %v", err)
	}

	// The stdlib ELF reader must still accept the modified binary.
	f, err := elf.NewFile(bytes.NewReader(signed))
	if err != nil {
		t.Fatalf("debug/elf cannot parse signed binary: %v", err)
	}
	defer f.Close()
	sec := f.Section(SectionName)
	if sec == nil {
		t.Fatal("debug/elf: no .peios.sig section in signed binary")
	}
	if sec.Type != elf.SHT_PROGBITS || sec.Size != BlobLen {
		t.Errorf("debug/elf: .peios.sig type=%v size=%d, want PROGBITS/%d", sec.Type, sec.Size, BlobLen)
	}
}
