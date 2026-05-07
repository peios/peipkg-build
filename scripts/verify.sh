#!/bin/sh
# verify.sh — validates a .peipkg against PSD-009 v0.22.
#
# This is a strict consumer-side validator. It checks:
#   - container format (zstd, pax tar, ustar/00, no PAX records for short paths)
#   - determinism rules (§3.1.4): mtime, uid/gid, owner/group, mode 0777
#   - entry order (§3.2.3): manifest first, files.json second, payload sorted,
#     optional .peipkg/signature last
#   - manifest schema (§3.3) — required fields present, types correct
#   - files.json schema (§3.5.1) — sorted, hashes match content
#   - per-payload size_installed sum (§3.3.6)
#   - signature envelope schema (§5.1.3) when .peipkg/signature is present
#
# Currently does NOT cover:
#   - cryptographic signature verification (§5.3) — envelope schema only;
#     Go-level tests perform the cryptographic check
#   - sd_overrides validation (§3.3.5)
#   - cross-spec dependency resolution
#
# Usage: verify.sh <peipkg-file>
# Exits 0 on pass, non-zero on first failure.

set -eu

PKG="$1"
if [ ! -f "$PKG" ]; then
  echo "FAIL: not a file: $PKG" >&2
  exit 1
fi

case "$PKG" in
  *.peipkg) ;;
  *) echo "FAIL: missing .peipkg extension: $PKG" >&2; exit 1 ;;
esac

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Decompress.
if ! zstd -d --stdout "$PKG" > "$WORK/archive.tar" 2> "$WORK/zstd.err"; then
  echo "FAIL: zstd decompression: $(cat "$WORK/zstd.err")" >&2
  exit 1
fi

# Run a Python validator for the tar-level checks. Python's tarfile gives us
# clean access to header fields, and we can enforce strict rules that GNU tar
# would silently smooth over.
python3 - "$WORK/archive.tar" << 'PY'
import sys, json, hashlib, tarfile, struct

ARCHIVE = sys.argv[1]
errors = []

def fail(msg):
    errors.append(msg)

# ---------------------------------------------------------------------------
# Pass 1: raw 512-byte block scan. Validates magic/version, typeflags, no PAX
# records for short-path archives, and ensures only the canonical 2 trailing
# zero blocks (no extra blocking-factor padding).
# ---------------------------------------------------------------------------
with open(ARCHIVE, "rb") as f:
    data = f.read()

if len(data) % 512 != 0:
    fail(f"archive size {len(data)} is not a multiple of 512")

i = 0
n = 0
zero_run = 0
content_blocks_remaining = 0
header_count = 0
while i < len(data):
    block = data[i:i+512]
    if content_blocks_remaining > 0:
        # part of a previous entry's content; do not interpret as header
        content_blocks_remaining -= 1
        i += 512
        n += 1
        continue
    if block == b"\x00" * 512:
        zero_run += 1
        i += 512
        n += 1
        continue
    if zero_run > 0:
        # we encountered non-zero after a zero run; that means the zero run
        # was actually data, not the trailer. shouldn't happen in well-formed
        # archives. but our archive.tar had only trailing zeros, so this is
        # a fail.
        fail(f"unexpected non-zero block after {zero_run} zero blocks at offset {i}")
        zero_run = 0

    name_field = block[0:100].rstrip(b"\x00").decode("utf-8", errors="replace")
    typeflag = chr(block[156]) if block[156] != 0 else "0"
    magic = block[257:263]
    version = block[263:265]
    uid_octal = block[108:116].rstrip(b"\x00 ").decode() or "0"
    gid_octal = block[116:124].rstrip(b"\x00 ").decode() or "0"
    mode_octal = block[100:108].rstrip(b"\x00 ").decode() or "0"
    mtime_octal = block[136:148].rstrip(b"\x00 ").decode() or "0"
    size_octal = block[124:136].rstrip(b"\x00 ").decode() or "0"
    uname = block[265:297].rstrip(b"\x00").decode("utf-8", errors="replace")
    gname = block[297:329].rstrip(b"\x00").decode("utf-8", errors="replace")
    devmajor = block[329:337].rstrip(b"\x00 ").decode() or "0"
    devminor = block[337:345].rstrip(b"\x00 ").decode() or "0"

    try:
        sz = int(size_octal, 8)
        uid = int(uid_octal, 8)
        gid = int(gid_octal, 8)
        mode = int(mode_octal, 8) & 0o7777
        mtime = int(mtime_octal, 8)
        dmaj = int(devmajor, 8)
        dmin = int(devminor, 8)
    except ValueError as e:
        fail(f"block {n}: octal parse error: {e}")
        sz = 0; mode = 0; uid = -1; gid = -1; mtime = 0; dmaj = -1; dmin = -1

    # §3.1.4 #8: ustar magic, "00" version
    if magic != b"ustar\x00":
        fail(f"block {n} {name_field!r}: bad magic {magic!r}")
    if version != b"00":
        fail(f"block {n} {name_field!r}: bad version {version!r}")
    # §3.1.4 #3: uid=0 gid=0
    if uid != 0:
        fail(f"block {n} {name_field!r}: uid {uid} (must be 0)")
    if gid != 0:
        fail(f"block {n} {name_field!r}: gid {gid} (must be 0)")
    # §3.1.4 #4: owner/group "root"
    if uname != "root":
        fail(f"block {n} {name_field!r}: uname {uname!r} (must be 'root')")
    if gname != "root":
        fail(f"block {n} {name_field!r}: gname {gname!r} (must be 'root')")
    # §3.1.4 #6: mode 0777, no setuid/setgid
    if mode != 0o777:
        fail(f"block {n} {name_field!r}: mode {oct(mode)} (must be 0o777)")
    # §3.1.4 #9: devmajor/devminor 0
    if dmaj != 0 or dmin != 0:
        fail(f"block {n} {name_field!r}: devmajor/devminor {dmaj}/{dmin} (must be 0)")
    # §3.1.4 #11: no PAX global headers
    if typeflag == "g":
        fail(f"block {n} {name_field!r}: PAX global header (typeflag 'g') forbidden")
    # §3.1.4 #12: PAX extended headers ('x') only when path or linkname > 100
    if typeflag == "x":
        fail(f"block {n} {name_field!r}: unexpected PAX extended header "
             f"(no payload path in this archive exceeds 100 bytes)")

    header_count += 1
    content_blocks_remaining = (sz + 511) // 512
    i += 512
    n += 1

# §3.1.4: archive ends with exactly two trailing zero blocks.
if zero_run != 2:
    fail(f"archive trailing zero-block count is {zero_run} (must be 2)")

# ---------------------------------------------------------------------------
# Pass 2: tarfile-based content checks. Manifest schema, files.json schema,
# entry order, mtime consistency, hash agreement.
# ---------------------------------------------------------------------------
with tarfile.open(ARCHIVE, mode="r:") as tf:
    members = tf.getmembers()

    if len(members) < 2:
        fail("archive must contain at least manifest.json and files.json")
        # short-circuit
        for e in errors: print(f"FAIL: {e}")
        sys.exit(1 if errors else 0)

    # §3.2.3 entry order
    if members[0].name != ".peipkg/manifest.json":
        fail(f"first entry {members[0].name!r} (must be .peipkg/manifest.json)")
    if members[1].name != ".peipkg/files.json":
        fail(f"second entry {members[1].name!r} (must be .peipkg/files.json)")

    # The optional .peipkg/signature entry, when present, MUST be the very
    # last entry (§3.2.3 step 4). Strip it from the payload set first so
    # the sort and reserved-prefix checks below see only payload.
    sig_member = None
    middle = members[2:]
    if middle and middle[-1].name == ".peipkg/signature":
        sig_member = middle[-1]
        middle = middle[:-1]
    elif any(m.name == ".peipkg/signature" for m in middle):
        offending = next(m for m in middle if m.name == ".peipkg/signature")
        fail(f"signature entry must be last in the archive (found at non-final position: {offending.name!r})")

    # Payload entries (everything after the metadata, before the signature)
    # must be sorted lex and MUST NOT use the reserved .peipkg/ prefix.
    payload = middle
    sorted_payload = sorted(payload, key=lambda m: m.name.encode("utf-8"))
    for a, b in zip(payload, sorted_payload):
        if a.name != b.name:
            fail(f"payload not lex-sorted: saw {a.name!r}, expected {b.name!r}")
            break

    for m in payload:
        if m.name.startswith(".peipkg/"):
            fail(f"payload entry uses reserved prefix: {m.name!r}")

    # Read manifest.
    mf = tf.extractfile(members[0])
    if mf is None:
        fail("could not extract manifest.json")
        for e in errors: print(f"FAIL: {e}")
        sys.exit(1)
    manifest_bytes = mf.read()
    if not manifest_bytes.endswith(b"\n"):
        fail("manifest.json must end with a single newline (§3.3.7)")
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as e:
        fail(f"manifest.json parse error: {e}")
        for e in errors: print(f"FAIL: {e}")
        sys.exit(1)

    # §3.3.2 required fields
    for fld in ("schema_version", "name", "version", "architecture",
                "dependencies", "conflicts", "size_installed", "build"):
        if fld not in manifest:
            fail(f"manifest missing required field: {fld}")
    if manifest.get("schema_version") != 1:
        fail(f"manifest schema_version {manifest.get('schema_version')} (must be 1)")

    # §3.3.4 build object
    build = manifest.get("build", {})
    for fld in ("timestamp", "farm_id", "source_ref"):
        if fld not in build:
            fail(f"manifest.build missing required field: {fld}")
    ts = build.get("timestamp", "")
    if not ts.endswith("Z"):
        fail(f"manifest.build.timestamp {ts!r} must end with 'Z' (§3.3.4)")

    # §3.1.4 #2: every entry's mtime equals manifest.build.timestamp.
    import datetime
    try:
        expected_epoch = int(datetime.datetime.fromisoformat(
            ts.replace("Z", "+00:00")).timestamp())
    except Exception as e:
        fail(f"manifest.build.timestamp not parseable: {e}")
        expected_epoch = None
    if expected_epoch is not None:
        for m in members:
            if m.mtime != expected_epoch:
                fail(f"entry {m.name!r} mtime {m.mtime} != manifest "
                     f"timestamp epoch {expected_epoch}")

    # Read files.json.
    ff = tf.extractfile(members[1])
    files_bytes = ff.read()
    try:
        files_json = json.loads(files_bytes)
    except json.JSONDecodeError as e:
        fail(f"files.json parse error: {e}")
        for e in errors: print(f"FAIL: {e}")
        sys.exit(1)

    if files_json.get("schema_version") != 1:
        fail(f"files.json schema_version {files_json.get('schema_version')} (must be 1)")
    if files_json.get("algorithm") != "sha256":
        fail(f"files.json algorithm {files_json.get('algorithm')!r} (v0.22 must be 'sha256')")

    # §3.5.1.3: entries sorted lex by path; one per regular-file payload entry.
    entries = files_json.get("entries", [])
    paths = [e["path"] for e in entries]
    if paths != sorted(paths, key=lambda p: p.encode("utf-8")):
        fail("files.json entries not lex-sorted by path")

    # Cross-check: regular-file payload entries == files.json entries.
    payload_files = {m.name: m for m in payload if m.isfile()}
    fjson_paths = {e["path"]: e for e in entries}
    if set(payload_files) != set(fjson_paths):
        only_tar = set(payload_files) - set(fjson_paths)
        only_json = set(fjson_paths) - set(payload_files)
        if only_tar:
            fail(f"payload files without files.json entry: {sorted(only_tar)}")
        if only_json:
            fail(f"files.json entries without payload file: {sorted(only_json)}")

    # Per-file hash + size check.
    total_size = 0
    for path, m in sorted(payload_files.items()):
        e = fjson_paths.get(path)
        if e is None: continue
        body = tf.extractfile(m).read()
        h = hashlib.sha256(body).hexdigest()
        if h != e["hash"]:
            fail(f"{path}: hash mismatch (computed {h}, manifest {e['hash']})")
        if len(body) != e["size"]:
            fail(f"{path}: size mismatch (file {len(body)}, manifest {e['size']})")
        total_size += len(body)

    # §3.3.6: size_installed == sum of file sizes.
    if manifest.get("size_installed") != total_size:
        fail(f"manifest.size_installed {manifest.get('size_installed')} != "
             f"sum of file sizes {total_size}")

    # §5.1.3 signature envelope schema check (when present).
    # Cryptographic verification is intentionally skipped here (the Go
    # tests cover that); this validator is responsible for the format-
    # level shape only.
    if sig_member is not None:
        sig_bytes = tf.extractfile(sig_member).read()
        if not sig_bytes.endswith(b"\n"):
            fail("signature envelope must end with a single newline")
        try:
            env = json.loads(sig_bytes)
        except json.JSONDecodeError as e:
            fail(f"signature envelope parse error: {e}")
            env = None
        if env is not None:
            if env.get("schema_version") != 1:
                fail(f"signature schema_version {env.get('schema_version')} (must be 1)")
            if env.get("algorithm") != "ed25519":
                fail(f"signature algorithm {env.get('algorithm')!r} (v0.22 must be 'ed25519')")
            fp = env.get("key_fingerprint", "")
            if not isinstance(fp, str) or len(fp) != 64 or any(c not in "0123456789abcdef" for c in fp):
                fail(f"signature key_fingerprint must be 64 lowercase hex chars (got {fp!r})")
            sig_b64 = env.get("signature", "")
            if not isinstance(sig_b64, str) or not sig_b64:
                fail(f"signature value missing or non-string")
            else:
                try:
                    import base64
                    decoded = base64.b64decode(sig_b64 + "==", validate=True)
                    if len(decoded) != 64:
                        fail(f"signature decoded length {len(decoded)} (Ed25519 signature is 64 bytes)")
                except Exception as e:
                    fail(f"signature value is not valid base64: {e}")

            # Strict envelope: only the four spec fields.
            allowed = {"schema_version", "algorithm", "key_fingerprint", "signature"}
            extra = set(env.keys()) - allowed
            if extra:
                fail(f"signature envelope has unexpected fields: {sorted(extra)}")

if errors:
    for e in errors:
        print(f"FAIL: {e}")
    sys.exit(1)
print("PASS")
PY
