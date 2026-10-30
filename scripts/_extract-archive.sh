#!/usr/bin/env bash
# _extract-archive.sh — robust blob-archive extractor shared by
# restore.sh and its tests.
#
# Usage:
#   scripts/_extract-archive.sh <archive.tgz> <target-dir>
#
# Guarantees:
#   - `target-dir` is created if it doesn't exist.
#   - Archive contents always land at `target-dir/...`, regardless of
#     whether the archive was taken with the new content-style layout
#     (`tar -C root -czf out.tgz .`) or the legacy named-top-dir
#     layout (`tar -C dirname -czf out.tgz basename`).
#   - Works even when the source and target basenames differ. The
#     legacy-layout detector only strips when every archive entry
#     shares a single non-"." top-level component.
#
# Detection:
#   The archive's top-level paths (first `/`-separated component) are
#   enumerated from `tar tzf`. We treat `.` as "no prefix" and compute
#   the distinct real-directory top-level components. If exactly one
#   exists AND it's a directory (not a file), we strip it with
#   `tar --strip-components=1`. Otherwise we extract as-is.
set -euo pipefail

die() { echo "$*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: $0 <archive.tgz> <target-dir>"
archive="$1"
target="$2"

[ -f "$archive" ] || die "no such archive: $archive"

mkdir -p "$target"

# Collect the set of top-level components from the archive. Omit empty
# lines and the bare "./" entries that content-style tars emit. The
# `||:` guards against the tar exit if it terminates early on very
# small archives.
entries="$(tar tzf "$archive" 2>/dev/null || true)"
tops="$(printf '%s\n' "$entries" \
  | awk -F/ '{print $1}' \
  | sed '/^$/d;/^\.$/d' \
  | sort -u)"
top_count="$(printf '%s\n' "$tops" | sed '/^$/d' | wc -l | tr -d ' ')"

# A directory entry looks like "foo/" (or "foo/bar"). A file entry at
# the top level is just "foo". When `top_count == 1` AND the entry
# appears followed by a `/` somewhere in the listing, it's a directory
# and we should strip one level.
strip=0
if [ "$top_count" = "1" ] && [ -n "$tops" ]; then
  top_name="$tops"
  # Any entry starting with "$top_name/" means top_name is a directory.
  if printf '%s\n' "$entries" | grep -qE "^${top_name}/"; then
    strip=1
  fi
fi

if [ "$strip" = "1" ]; then
  echo "  extract: legacy layout (top='${tops}') — stripping one level into $target"
  tar -C "$target" --strip-components=1 -xzf "$archive"
else
  echo "  extract: content-style — unpacking into $target"
  tar -C "$target" -xzf "$archive"
fi
