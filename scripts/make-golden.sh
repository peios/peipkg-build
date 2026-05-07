#!/bin/sh
# make-golden.sh — shell reference implementation of peipkg emission.
#
# Produces a single .peipkg file from a case directory. Goal: byte-for-byte
# spec-conformant output (PSD-009 §3) we can hold the Go tool to.
#
# This is intentionally verbose and step-by-step. Read it alongside the spec.
#
# Usage: make-golden.sh <case-dir> <version> <timestamp> <farm-id> <source-ref> <out-path>
#   case-dir:   path to testdata/cases/<name>/
#   version:    e.g. "0.1-1"
#   timestamp:  RFC 3339 UTC (must end with Z), e.g. "2026-05-06T12:00:00Z"
#   farm-id:    e.g. "test-farm-1"
#   source-ref: e.g. "test://hello-noarch"
#   out-path:   destination .peipkg
#
# Currently supports the hello-noarch case (single noarch package, unsigned).
# Extension to signing / multi-package / etc. comes later.

set -eu

CASE_DIR="$1"
VERSION="$2"
TIMESTAMP="$3"
FARM_ID="$4"
SOURCE_REF="$5"
OUT="$6"

if [ ! -d "$CASE_DIR" ]; then
  echo "case-dir does not exist: $CASE_DIR" >&2
  exit 1
fi

# Recipe parsing — for now, hardcoded for hello-noarch.
# Real tool will read peipkg.toml.
NAME="hello"
ARCH="noarch"
DESCRIPTION="Smallest legal peipkg test fixture."
LICENSE="CC0-1.0"
HOMEPAGE="https://peios.org"

EPOCH=$(date -u -d "$TIMESTAMP" +%s)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Step 1: run build.sh into a fresh DESTDIR.
# ---------------------------------------------------------------------------
DESTDIR="$WORK/destdir"
mkdir -p "$DESTDIR"

SOURCE_DIR="$CASE_DIR/staged" \
DESTDIR="$DESTDIR" \
SOURCE_DATE_EPOCH="$EPOCH" \
LC_ALL=C TZ=UTC \
PATH="$PATH" \
sh "$CASE_DIR/recipe/build.sh"

# ---------------------------------------------------------------------------
# Step 2: walk DESTDIR, compute per-file hashes, build files.json input.
# ---------------------------------------------------------------------------
# Files are sorted by path (LC_ALL=C lex order = byte order for ASCII paths).
FILE_LIST="$WORK/file-list"
( cd "$DESTDIR" && find . -type f | sed 's|^\./||' ) | LC_ALL=C sort > "$FILE_LIST"

SIZE_INSTALLED=0
ENTRIES_TMP="$WORK/entries.json"
echo "[" > "$ENTRIES_TMP"
FIRST=1
while IFS= read -r f; do
  size=$(stat -c %s "$DESTDIR/$f")
  hash=$(sha256sum "$DESTDIR/$f" | awk '{print $1}')
  SIZE_INSTALLED=$((SIZE_INSTALLED + size))
  if [ "$FIRST" = "1" ]; then
    FIRST=0
  else
    printf "," >> "$ENTRIES_TMP"
  fi
  # Use jq to safely escape path strings.
  jq -nc --arg path "$f" --argjson size "$size" --arg hash "$hash" \
    '{path: $path, size: $size, hash: $hash}' >> "$ENTRIES_TMP"
done < "$FILE_LIST"
echo "]" >> "$ENTRIES_TMP"

ENTRIES_JSON=$(jq -c '.' "$ENTRIES_TMP")

# ---------------------------------------------------------------------------
# Step 3: assemble metadata files (.peipkg/manifest.json, .peipkg/files.json).
# ---------------------------------------------------------------------------
# Stage everything that goes into the tar under $ARCHIVE.
ARCHIVE="$WORK/archive"
mkdir -p "$ARCHIVE/.peipkg"

# files.json — compact JSON, single trailing newline.
jq -nc \
  --argjson entries "$ENTRIES_JSON" \
  '{schema_version: 1, algorithm: "sha256", entries: $entries}' \
  > "$ARCHIVE/.peipkg/files.json"

# manifest.json — compact JSON, single trailing newline.
# Field order matches §9.1 schema layout (schema_version first, build last).
jq -nc \
  --arg name "$NAME" \
  --arg version "$VERSION" \
  --arg arch "$ARCH" \
  --arg description "$DESCRIPTION" \
  --arg license "$LICENSE" \
  --arg homepage "$HOMEPAGE" \
  --argjson size_installed "$SIZE_INSTALLED" \
  --arg timestamp "$TIMESTAMP" \
  --arg farm_id "$FARM_ID" \
  --arg source_ref "$SOURCE_REF" \
  '{
    schema_version: 1,
    name: $name,
    version: $version,
    architecture: $arch,
    description: $description,
    license: $license,
    homepage: $homepage,
    dependencies: [],
    optional_dependencies: [],
    conflicts: [],
    provides: [],
    replaces: [],
    side_effects: [],
    size_installed: $size_installed,
    sd_overrides: [],
    build: {
      timestamp: $timestamp,
      farm_id: $farm_id,
      source_ref: $source_ref
    }
  }' > "$ARCHIVE/.peipkg/manifest.json"

# Copy payload (everything from DESTDIR) into the archive staging area.
cp -a "$DESTDIR/." "$ARCHIVE/"

# ---------------------------------------------------------------------------
# Step 4: assemble the tar entries list in canonical order.
# Order per §3.2.3:
#   1. .peipkg/manifest.json
#   2. .peipkg/files.json
#   3. payload entries, sorted lex
# (Then the signature entry — skipped here, this case is unsigned.)
#
# We include payload directories so extraction into an empty tree works.
# Strict directory-ownership across packages is a future concern.
# ---------------------------------------------------------------------------
ENTRIES_LIST="$WORK/tar-entries"
{
  echo ".peipkg/manifest.json"
  echo ".peipkg/files.json"
  # All payload entries (excluding metadata), sorted.
  ( cd "$ARCHIVE" && find . -mindepth 1 \
      ! -path './.peipkg' \
      ! -path './.peipkg/*' \
      \( -type f -o -type d -o -type l \) ) \
    | sed 's|^\./||' | LC_ALL=C sort
} > "$ENTRIES_LIST"

# ---------------------------------------------------------------------------
# Step 5: emit the tar with deterministic flags.
# Spec §3.1.4 rules:
#   #1 entries lex-sorted by path -> handled via -T list
#   #2 mtime = build.timestamp on every entry -> --mtime=@EPOCH
#   #3 owner uid=0, group gid=0 -> --owner=root:0 --group=root:0
#   #4 owner name="root", group name="root" -> same flag form
#   #5 no xattrs -> GNU tar default (no --xattrs)
#   #7,#12 only path/linkpath PAX records, ONLY when name>100 -> --pax-option=delete=*
#   #8 ustar magic, "00" version -> --format=pax produces this
#   #9 devmajor=devminor=0 -> default for non-device entries
#   #10 NUL padding -> tar default
#   #11 no PAX global header (typeflag g) -> verified by inspection
# ---------------------------------------------------------------------------
( cd "$ARCHIVE" && \
  tar --format=pax \
      --owner=root:0 --group=root:0 \
      --mode=0777 \
      --mtime=@"$EPOCH" \
      --no-recursion \
      --blocking-factor=1 \
      --pax-option='delete=atime,delete=ctime,delete=mtime' \
      -T "$ENTRIES_LIST" \
      -cf "$WORK/archive.tar"
)

# ---------------------------------------------------------------------------
# Step 6: compress with zstd.
# Spec §3.1.3 leaves level at producer's discretion. We use --no-check to
# omit the trailing XXH64 frame checksum, since the spec doesn't require it
# and omitting keeps the file minimal/deterministic.
# ---------------------------------------------------------------------------
zstd -19 --no-check -q -f -o "$OUT" "$WORK/archive.tar"

echo "wrote $OUT ($(stat -c %s "$OUT") bytes)"
