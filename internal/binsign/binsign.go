// Package binsign produces Peios binary signatures: the `.peios.sig` ELF
// section the kernel verifies at exec to assign PIP trust (pip_type/pip_trust).
//
// This is SEPARATE from package (.peipkg) signing in internal/signature —
// different key, carrier, verifier, and job. See peios/binary-signing-design.md.
//
// The format is dictated by the kernel verifier (pkm/kacs/lsm.c, ~5294-6135).
// Any drift here silently yields binaries the kernel treats as unsigned, so the
// constants and hash rule below MUST mirror lsm.c exactly:
//
//   - Carrier: ELF section ".peios.sig", SHT_PROGBITS, exactly 65 bytes.
//   - Blob: byte 0 = version 0x01; bytes 1..65 = 64-byte Ed25519 signature.
//   - Hash: SHA-256 over the whole file with the 65 section-content bytes (at
//     the section's file offset) treated as zero.
//   - Signature: Ed25519 over the 32-byte SHA-256 digest as the message.
//   - Catalogue: the kernel trusts a key iff its raw 32-byte public key is in
//     the compiled-in table; v0.20 has one entry (the TCB key).
//
// Signing MUST be the last mutation of a binary: any later strip/objcopy
// invalidates the signature.
package binsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

const (
	// SectionName is the ELF section that carries the signature blob.
	SectionName = ".peios.sig"
	// BlobLen is the exact section size: version byte + signature.
	BlobLen = 65
	// SignatureLen is the Ed25519 signature length.
	SignatureLen = 64
	// Version is the blob version byte (PKM_KACS_SIGNING_VERSION).
	Version = 0x01
)

// Sentinel errors, exported for callers and tests.
var (
	ErrNotELF64      = errors.New("binsign: not a little-endian ELF64 binary")
	ErrNoSections    = errors.New("binsign: ELF has no usable section header table")
	ErrMalformedELF  = errors.New("binsign: malformed ELF section table")
	ErrAlreadySigned = errors.New("binsign: ELF already has a " + SectionName + " section")
	ErrVerifyFailed  = errors.New("binsign: post-sign self-verification failed")
)

// Signer produces an Ed25519 signature over a 32-byte SHA-256 digest. It is
// the seam that lets the private key live in-process today (KeySigner) and
// behind an external signer / HSM later, without touching the ELF logic.
type Signer interface {
	// SignDigest returns a 64-byte Ed25519 signature over digest (32 bytes).
	SignDigest(digest []byte) ([]byte, error)
	// Public returns the raw 32-byte Ed25519 public key, used for the
	// post-sign self-check.
	Public() ed25519.PublicKey
}

// KeySigner is an in-process Signer backed by an Ed25519 private key.
type KeySigner struct{ priv ed25519.PrivateKey }

// NewKeySigner wraps an Ed25519 private key (as loaded by internal/signature).
func NewKeySigner(priv ed25519.PrivateKey) (*KeySigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("binsign: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &KeySigner{priv: priv}, nil
}

// SignDigest signs the 32-byte digest as the Ed25519 message, matching the
// kernel's crypto_sig_verify(tfm, sig, 64, hash, 32).
func (k *KeySigner) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("binsign: digest is %d bytes, want %d", len(digest), sha256.Size)
	}
	return ed25519.Sign(k.priv, digest), nil
}

// Public returns the raw 32-byte Ed25519 public key.
func (k *KeySigner) Public() ed25519.PublicKey {
	return k.priv.Public().(ed25519.PublicKey)
}

// SignELF embeds a .peios.sig signature into the ELF file at path, in place,
// preserving the file mode. It is idempotency-safe: a file that already carries
// a .peios.sig section is rejected (ErrAlreadySigned) rather than double-signed.
func SignELF(path string, signer Signer) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	signed, err := signBytes(raw, signer)
	if err != nil {
		return fmt.Errorf("sign %s: %w", path, err)
	}

	// Atomic replace, preserving permissions (the executable bit matters).
	tmp := path + ".peios-sig.tmp"
	if err := os.WriteFile(tmp, signed, info.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// signBytes is the pure core: it returns a new copy of raw carrying a populated
// .peios.sig section. Split from SignELF for in-memory testing.
func signBytes(raw []byte, signer Signer) ([]byte, error) {
	out, sigOffset, err := addZeroedSigSection(raw)
	if err != nil {
		return nil, err
	}

	// Hash with the section content zeroed (it is zero in `out` already).
	digest := digestZeroed(out, sigOffset)
	sig, err := signer.SignDigest(digest)
	if err != nil {
		return nil, err
	}
	if len(sig) != SignatureLen {
		return nil, fmt.Errorf("binsign: signer returned %d-byte signature, want %d", len(sig), SignatureLen)
	}

	// Populate the blob in place: version byte + signature. No layout change,
	// so the digest the kernel recomputes (zeroing these bytes) still matches.
	out[sigOffset] = Version
	copy(out[sigOffset+1:sigOffset+BlobLen], sig)

	// Self-verify against the kernel's exact rule before returning. Cheap
	// insurance against a silently-unverifiable binary.
	if err := verifyBytes(out, signer.Public()); err != nil {
		return nil, ErrVerifyFailed
	}
	return out, nil
}

// addZeroedSigSection returns a new ELF with an appended, zero-filled
// .peios.sig section (SHT_PROGBITS, 65 bytes) and the offset of its content.
//
// Strategy: append everything new at end of file so existing section offsets
// are undisturbed. A fresh shstrtab (old bytes + the new name) is appended and
// the shstrtab section header repointed at it; the section header table is
// rebuilt with one extra entry and appended; e_shoff/e_shnum are patched.
func addZeroedSigSection(raw []byte) (out []byte, sigOffset int, err error) {
	eh, sections, strtab, strtabIdx, err := parseELF(raw)
	if err != nil {
		return nil, 0, err
	}

	for i := range sections {
		if cString(strtab, sections[i].Name) == SectionName {
			return nil, 0, ErrAlreadySigned
		}
	}

	// New shstrtab = old + ".peios.sig\0"; new name's offset is the old length.
	newNameOff := uint32(len(strtab))
	newStrtab := make([]byte, 0, len(strtab)+len(SectionName)+1)
	newStrtab = append(newStrtab, strtab...)
	newStrtab = append(newStrtab, SectionName...)
	newStrtab = append(newStrtab, 0)

	out = make([]byte, len(raw))
	copy(out, raw)

	// 1. Append the 65-byte signature section content (zeroed placeholder).
	sigOffset = len(out)
	out = append(out, make([]byte, BlobLen)...)

	// 2. Append the relocated shstrtab.
	newStrtabOff := len(out)
	out = append(out, newStrtab...)

	// 3. Pad to 8-byte alignment for the section header table.
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	newShtOff := len(out)

	// 4. Rebuild the section header table: copy old entries, repoint the
	//    shstrtab entry, append the .peios.sig entry.
	newSections := make([]elf.Section64, len(sections)+1)
	copy(newSections, sections)
	newSections[strtabIdx].Off = uint64(newStrtabOff)
	newSections[strtabIdx].Size = uint64(len(newStrtab))
	newSections[len(sections)] = elf.Section64{
		Name:      newNameOff,
		Type:      uint32(elf.SHT_PROGBITS),
		Addralign: 1,
		Off:       uint64(sigOffset),
		Size:      BlobLen,
	}
	var sht bytes.Buffer
	for i := range newSections {
		if err := binary.Write(&sht, binary.LittleEndian, &newSections[i]); err != nil {
			return nil, 0, err
		}
	}
	out = append(out, sht.Bytes()...)

	// 5. Patch the ELF header: section table offset and count.
	eh.Shoff = uint64(newShtOff)
	eh.Shnum = uint16(len(newSections))
	var hb bytes.Buffer
	if err := binary.Write(&hb, binary.LittleEndian, &eh); err != nil {
		return nil, 0, err
	}
	copy(out[:hb.Len()], hb.Bytes())

	return out, sigOffset, nil
}

// verifyBytes mirrors the kernel's exec-time check: find .peios.sig, validate
// the blob, hash the file with the section zeroed, and Ed25519-verify against
// pub. It is both SignELF's self-check and the test oracle.
func verifyBytes(raw []byte, pub ed25519.PublicKey) error {
	_, sections, strtab, _, err := parseELF(raw)
	if err != nil {
		return err
	}
	for i := range sections {
		if cString(strtab, sections[i].Name) != SectionName {
			continue
		}
		s := sections[i]
		if s.Type != uint32(elf.SHT_PROGBITS) || s.Size != BlobLen {
			return ErrMalformedELF
		}
		off := int(s.Off)
		if off < 0 || off+BlobLen > len(raw) || off+BlobLen < off {
			return ErrMalformedELF
		}
		blob := raw[off : off+BlobLen]
		if blob[0] != Version {
			return ErrMalformedELF
		}
		if !ed25519.Verify(pub, digestZeroed(raw, off), blob[1:BlobLen]) {
			return ErrVerifyFailed
		}
		return nil
	}
	return fmt.Errorf("binsign: no %s section found", SectionName)
}

// digestZeroed returns SHA-256 over raw with the BlobLen bytes at off treated
// as zero, matching pkm_kacs_signing_hash_buffer.
func digestZeroed(raw []byte, off int) []byte {
	h := sha256.New()
	h.Write(raw[:off])
	var zeros [BlobLen]byte
	h.Write(zeros[:])
	h.Write(raw[off+BlobLen:])
	return h.Sum(nil)
}

// parseELF validates that raw is a little-endian ELF64 with a usable section
// header table, and returns its header, section headers, the section-name
// string table, and the strtab section index.
func parseELF(raw []byte) (eh elf.Header64, sections []elf.Section64, strtab []byte, strtabIdx int, err error) {
	hdrSize := binary.Size(elf.Header64{})
	if len(raw) < hdrSize ||
		!bytes.HasPrefix(raw, []byte(elf.ELFMAG)) ||
		raw[elf.EI_CLASS] != byte(elf.ELFCLASS64) ||
		raw[elf.EI_DATA] != byte(elf.ELFDATA2LSB) {
		return eh, nil, nil, 0, ErrNotELF64
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &eh); err != nil {
		return eh, nil, nil, 0, err
	}
	if eh.Shentsize != uint16(binary.Size(elf.Section64{})) || eh.Shnum == 0 {
		return eh, nil, nil, 0, ErrNoSections
	}
	if eh.Shstrndx == uint16(elf.SHN_UNDEF) || eh.Shstrndx >= eh.Shnum {
		return eh, nil, nil, 0, ErrMalformedELF
	}

	shtOff := int(eh.Shoff)
	entSize := int(eh.Shentsize)
	shnum := int(eh.Shnum)
	end := shtOff + shnum*entSize
	if shtOff <= 0 || end > len(raw) || end < shtOff {
		return eh, nil, nil, 0, ErrMalformedELF
	}

	sections = make([]elf.Section64, shnum)
	for i := range shnum {
		off := shtOff + i*entSize
		if err := binary.Read(bytes.NewReader(raw[off:off+entSize]), binary.LittleEndian, &sections[i]); err != nil {
			return eh, nil, nil, 0, err
		}
	}

	strtabIdx = int(eh.Shstrndx)
	ss := sections[strtabIdx]
	sOff, sSize := int(ss.Off), int(ss.Size)
	if sOff < 0 || sSize < 0 || sOff+sSize > len(raw) || sOff+sSize < sOff {
		return eh, nil, nil, 0, ErrMalformedELF
	}
	strtab = raw[sOff : sOff+sSize]
	return eh, sections, strtab, strtabIdx, nil
}

// cString reads the NUL-terminated string at off in strtab.
func cString(strtab []byte, off uint32) string {
	if int(off) >= len(strtab) {
		return ""
	}
	name, _, _ := bytes.Cut(strtab[off:], []byte{0})
	return string(name)
}
