// Package pack emits a single .peipkg from a staged tree and a manifest.
//
// Pack is the deterministic core of peipkg-build. It does not parse recipes,
// run build scripts, or partition multi-package outputs — that is the
// internal/builder package's job. Pack takes a staged tree on disk plus the
// manifest fields the caller has resolved, and produces a byte-stable
// .peipkg conforming to PSD-009 v0.22 §3.
//
// All output bytes are determined by Pack's inputs. Given identical inputs,
// two invocations produce byte-identical output. The reproducibility primitive
// is "same peipkg-build version, same inputs, same bytes" — see
// peipkg-build/DESIGN.md "Reproducibility / determinism" for the model.
package pack

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/peios/peipkg-build/internal/files"
	"github.com/peios/peipkg-build/internal/manifest"
	"github.com/peios/peipkg-build/internal/signature"
)

// Input is everything Pack needs to emit one .peipkg.
//
// SchemaVersion and SizeInstalled in Manifest are filled by Pack and any
// values pre-set by the caller are overwritten. Build is consumed as-is and
// must be valid; Manifest.Build.Timestamp drives every tar entry's mtime
// (§3.1.4 #2).
//
// Selector, when non-nil, is consulted for every regular file and symlink
// encountered in StagedRoot. The selector receives a slash-separated path
// relative to StagedRoot (no leading slash) and returns true to include the
// entry. A nil Selector includes everything. Directory entries are derived:
// any directory that is an ancestor of an included file or symlink is
// emitted, with no further filtering.
//
// SignKey, when non-empty, signs the package per §5.1. Pack appends a
// .peipkg/signature entry as the final tar entry, computed over the
// uncompressed bytes of every preceding entry. A nil or empty SignKey
// produces an unsigned package (still spec-conformant per §5.1.7).
//
// Out receives the compressed .peipkg bytes. Pack streams its output and does
// not seek; Out may be a file, a buffer, or a network sink.
type Input struct {
	StagedRoot string
	Selector   func(path string) bool
	Manifest   manifest.Manifest
	SignKey    ed25519.PrivateKey
	Out        io.Writer
}

// Pack assembles and writes one .peipkg.
//
// The high-level flow:
//
//  1. Walk StagedRoot to discover entries and apply Selector.
//  2. Hash each included regular file (SHA-256) and build the integrity
//     manifest (§3.5.1).
//  3. Synthesize the directory entries needed to cover every included leaf,
//     so that a consumer extracting the archive into an empty tree finds the
//     directory hierarchy intact.
//  4. Sort all entries lexicographically by their on-wire path bytes
//     (§3.1.4 #1).
//  5. Encode the manifest and integrity manifest as canonical JSON.
//  6. Write the tar archive in the order required by §3.2.3 (manifest first,
//     then integrity manifest, then payload), wrapping the writer in a zstd
//     frame.
func Pack(in Input) error {
	if in.StagedRoot == "" {
		return fmt.Errorf("pack: StagedRoot is required")
	}
	if in.Out == nil {
		return fmt.Errorf("pack: Out is required")
	}

	mtime, err := in.Manifest.Build.ModTime()
	if err != nil {
		return fmt.Errorf("pack: parse build.timestamp: %w", err)
	}

	leaves, err := walkLeaves(in.StagedRoot, in.Selector)
	if err != nil {
		return fmt.Errorf("pack: walk staged tree: %w", err)
	}

	integrity, totalSize, err := buildIntegrityManifest(in.StagedRoot, leaves)
	if err != nil {
		return fmt.Errorf("pack: hash payload files: %w", err)
	}

	allEntries := withAncestorDirs(leaves)
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].path < allEntries[j].path
	})

	m := in.Manifest
	m.SchemaVersion = manifest.SchemaVersion
	m.SizeInstalled = totalSize

	manifestBytes, err := manifest.Encode(m)
	if err != nil {
		return fmt.Errorf("pack: encode manifest: %w", err)
	}
	filesBytes, err := files.Encode(integrity)
	if err != nil {
		return fmt.Errorf("pack: encode integrity manifest: %w", err)
	}

	zw, err := zstd.NewWriter(in.Out,
		zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderCRC(false),
	)
	if err != nil {
		return fmt.Errorf("pack: init zstd encoder: %w", err)
	}

	if err := writeArchive(zw, manifestBytes, filesBytes, in.StagedRoot, allEntries, mtime, in.SignKey); err != nil {
		// Close the encoder to release resources, but propagate the original
		// write error rather than any close error: the original is the cause.
		_ = zw.Close()
		return fmt.Errorf("pack: write archive: %w", err)
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("pack: close zstd encoder: %w", err)
	}
	return nil
}

// entryKind distinguishes the three permitted payload entry types (§3.4).
type entryKind int

const (
	kindFile entryKind = iota
	kindDir
	kindSymlink
)

// entry is one tar entry awaiting emission. path is the slash-separated
// archive path with no leading slash and no trailing slash; the trailing
// slash for directory entries is added at tar-emission time.
type entry struct {
	path       string
	kind       entryKind
	size       int64  // regular files only
	linkTarget string // symlinks only
}

// walkLeaves discovers every regular file, symlink, and explicitly selected
// directory under stagedRoot. Ancestor directories that are not selected here
// are synthesized separately by withAncestorDirs.
//
// Special files (devices, FIFOs, sockets, hardlinks) are rejected: §3.4.4
// permits only regular files, directories, and symlinks. A walk that
// encounters a forbidden type fails the whole pack rather than silently
// dropping the entry.
func walkLeaves(stagedRoot string, selector func(string) bool) ([]entry, error) {
	var leaves []entry

	walkErr := filepath.WalkDir(stagedRoot, func(p string, d os.DirEntry, err error) error {
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
			if selector != nil && selector(rel) {
				leaves = append(leaves, entry{path: rel, kind: kindDir})
			}
			return nil
		case d.Type()&os.ModeSymlink != 0:
			if selector != nil && !selector(rel) {
				return nil
			}
			target, err := os.Readlink(p)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", rel, err)
			}
			leaves = append(leaves, entry{path: rel, kind: kindSymlink, linkTarget: target})
			return nil
		case d.Type().IsRegular():
			if selector != nil && !selector(rel) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("stat %s: %w", rel, err)
			}
			leaves = append(leaves, entry{path: rel, kind: kindFile, size: info.Size()})
			return nil
		default:
			return fmt.Errorf("%s: unsupported entry type %v (PSD-009 §3.4 permits only regular files, directories, and symlinks)", rel, d.Type())
		}
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return leaves, nil
}

// withAncestorDirs returns leaves plus a directory entry for every distinct
// ancestor path. The result is unsorted; the caller sorts before emission.
//
// The ancestor set is derived from the leaves rather than from the disk walk
// so that multi-package builds emit only the directories each stanza
// actually owns. Two stanzas claiming files in the same parent directory
// each emit their own directory entry; per §3.2.3 the consumer's mkdir is
// idempotent.
func withAncestorDirs(leaves []entry) []entry {
	seen := make(map[string]struct{}, len(leaves)*2)
	out := make([]entry, 0, len(leaves)*2)
	out = append(out, leaves...)
	for _, e := range leaves {
		if e.kind == kindDir {
			seen[e.path] = struct{}{}
		}
	}

	for _, e := range leaves {
		for _, anc := range ancestorsOf(e.path) {
			if _, ok := seen[anc]; ok {
				continue
			}
			seen[anc] = struct{}{}
			out = append(out, entry{path: anc, kind: kindDir})
		}
	}
	return out
}

// ancestorsOf returns the sequence of parent directories of p, from the
// shallowest (immediate child of root) to the deepest. The path itself is
// not included.
//
// ancestorsOf("usr/share/hello/MESSAGE") -> ["usr", "usr/share", "usr/share/hello"]
func ancestorsOf(p string) []string {
	parts := strings.Split(p, "/")
	if len(parts) <= 1 {
		return nil
	}
	out := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// buildIntegrityManifest computes the §3.5.1 integrity manifest. Entries
// match the leaves' file order, which the caller will subsequently re-sort
// during overall entry sorting; the integrity manifest is then sorted
// independently by path bytes (§3.5.1.3).
func buildIntegrityManifest(stagedRoot string, leaves []entry) (files.Manifest, int64, error) {
	var entries []files.Entry
	var total int64

	for _, e := range leaves {
		if e.kind != kindFile {
			continue
		}
		hash, size, err := hashStagedFile(stagedRoot, e.path)
		if err != nil {
			return files.Manifest{}, 0, err
		}
		if size != e.size {
			return files.Manifest{}, 0, fmt.Errorf("%s: file changed during pack (was %d bytes at walk, %d at hash)", e.path, e.size, size)
		}
		entries = append(entries, files.Entry{Path: e.path, Size: size, Hash: hash})
		total += size
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })

	return files.Manifest{
		SchemaVersion: files.SchemaVersion,
		Algorithm:     files.Algorithm,
		Entries:       entries,
	}, total, nil
}

func hashStagedFile(stagedRoot, relPath string) (string, int64, error) {
	f, err := os.Open(filepath.Join(stagedRoot, relPath))
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", relPath, err)
	}
	defer f.Close()

	hash, size, err := files.HashFile(f)
	if err != nil {
		return "", 0, fmt.Errorf("hash %s: %w", relPath, err)
	}
	return hash, size, nil
}

// writeArchive emits the tar archive in the order specified by §3.2.3:
// manifest first, integrity manifest second, payload entries (already
// sorted) third, and the signature entry last when signKey is non-empty.
// Each entry is written with canonical header fields per §3.1.4.
//
// When signing, the writer is wrapped in an io.MultiWriter that also feeds
// a SHA-256 hasher; the hasher captures the uncompressed bytes of every
// pre-signature entry, including their content-block padding. After the
// last payload entry is written, tw.Flush() emits any pending padding to
// the hasher, the digest is read, and the hasher is then "stopped" so the
// signature entry's own bytes don't pollute the digest.
func writeArchive(w io.Writer, manifestBytes, filesBytes []byte, stagedRoot string, entries []entry, mtime time.Time, signKey ed25519.PrivateKey) error {
	var hasher *stoppingHasher
	target := w
	if len(signKey) > 0 {
		hasher = &stoppingHasher{Hash: sha256.New()}
		target = io.MultiWriter(w, hasher)
	}

	tw := tar.NewWriter(target)

	if err := writeBlobEntry(tw, ".peipkg/manifest.json", manifestBytes, mtime); err != nil {
		return err
	}
	if err := writeBlobEntry(tw, ".peipkg/files.json", filesBytes, mtime); err != nil {
		return err
	}
	for _, e := range entries {
		if err := writePayloadEntry(tw, stagedRoot, e, mtime); err != nil {
			return err
		}
	}

	if hasher != nil {
		// Flush the last entry's content-block padding into the hasher
		// before we read the digest. tar.Writer would emit this padding
		// implicitly at the next WriteHeader, but at that point the
		// hasher is already stopped.
		if err := tw.Flush(); err != nil {
			return fmt.Errorf("flush pre-signature padding: %w", err)
		}
		digest := hasher.Sum(nil)
		hasher.stop()

		envBytes, err := signature.Encode(signature.Sign(signKey, digest))
		if err != nil {
			return fmt.Errorf("encode signature envelope: %w", err)
		}
		if err := writeBlobEntry(tw, signature.EntryPath, envBytes, mtime); err != nil {
			return err
		}
	}

	// Close flushes the two zero blocks that mark the end of a tar archive.
	return tw.Close()
}

// stoppingHasher is a hash.Hash that ignores Writes after stop() is called.
// It exists to let MultiWriter feed both the compressor and the hasher up
// to a chosen point, after which only the compressor receives bytes.
//
// Without this indirection we would either need to swap the tar.Writer's
// underlying io.Writer mid-stream (the API does not permit this) or
// buffer the entire pre-signature tar for hashing in one shot (avoidable
// memory cost).
type stoppingHasher struct {
	hash.Hash
	stopped bool
}

func (s *stoppingHasher) Write(p []byte) (int, error) {
	if s.stopped {
		return len(p), nil
	}
	return s.Hash.Write(p)
}

func (s *stoppingHasher) stop() { s.stopped = true }

// canonicalHeader builds a tar header with every field set to the value
// §3.1.4 mandates. The caller fills in Typeflag, Size, and Linkname for the
// specific entry type.
//
// AccessTime and ChangeTime are deliberately left as time.Time{} (the zero
// value) so that archive/tar in FormatPAX mode does not emit `atime` or
// `ctime` PAX records (§3.1.4 #12 forbids those records). ModTime is the
// build timestamp, also expressible in ustar's 12-octal mtime field for any
// realistic build year, so no `mtime` PAX record is emitted either.
//
// Devmajor and Devminor are zero by default because we never write device
// entries (§3.1.4 #9).
func canonicalHeader(name string, mtime time.Time) *tar.Header {
	return &tar.Header{
		Name:    name,
		Mode:    0o777,
		Uid:     0,
		Gid:     0,
		Uname:   "root",
		Gname:   "root",
		ModTime: mtime,
		Format:  tar.FormatPAX,
	}
}

// writeBlobEntry writes a regular file whose body is held in memory
// (manifest.json, files.json).
func writeBlobEntry(tw *tar.Writer, name string, body []byte, mtime time.Time) error {
	h := canonicalHeader(name, mtime)
	h.Typeflag = tar.TypeReg
	h.Size = int64(len(body))
	if err := tw.WriteHeader(h); err != nil {
		return fmt.Errorf("tar header for %s: %w", name, err)
	}
	if _, err := tw.Write(body); err != nil {
		return fmt.Errorf("tar body for %s: %w", name, err)
	}
	return nil
}

// writePayloadEntry writes one payload entry (file, directory, or symlink)
// drawn from the staged tree on disk.
func writePayloadEntry(tw *tar.Writer, stagedRoot string, e entry, mtime time.Time) error {
	switch e.kind {
	case kindDir:
		// POSIX pax mandates a trailing slash on directory entry names so
		// that consumers can disambiguate a directory from a regular file
		// with the same name (§3.4 permits both forms in the namespace,
		// distinguished by typeflag).
		h := canonicalHeader(e.path+"/", mtime)
		h.Typeflag = tar.TypeDir
		if err := tw.WriteHeader(h); err != nil {
			return fmt.Errorf("tar header for dir %s: %w", e.path, err)
		}
		return nil

	case kindSymlink:
		h := canonicalHeader(e.path, mtime)
		h.Typeflag = tar.TypeSymlink
		h.Linkname = e.linkTarget
		if err := tw.WriteHeader(h); err != nil {
			return fmt.Errorf("tar header for symlink %s: %w", e.path, err)
		}
		return nil

	case kindFile:
		h := canonicalHeader(e.path, mtime)
		h.Typeflag = tar.TypeReg
		h.Size = e.size
		if err := tw.WriteHeader(h); err != nil {
			return fmt.Errorf("tar header for file %s: %w", e.path, err)
		}
		f, err := os.Open(filepath.Join(stagedRoot, e.path))
		if err != nil {
			return fmt.Errorf("open file %s: %w", e.path, err)
		}
		defer f.Close()

		n, err := io.Copy(tw, f)
		if err != nil {
			return fmt.Errorf("write body for %s: %w", e.path, err)
		}
		if n != e.size {
			return fmt.Errorf("%s: short write (wrote %d bytes, header declared %d)", e.path, n, e.size)
		}
		return nil

	default:
		return fmt.Errorf("internal: unknown entry kind %d for %s", e.kind, e.path)
	}
}
