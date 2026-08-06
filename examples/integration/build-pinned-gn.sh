#!/bin/sh
set -eu

revision=64cfb8344ec3e8585a89a3836716a026e2771fcb
destination=${1:-${TMPDIR:-/tmp}/chromifer-gn}

if [ -x "$destination/out/gn" ] && [ -d "$destination/.git" ]; then
  current=$(git -C "$destination" rev-parse HEAD)
  if [ "$current" = "$revision" ]; then
    "$destination/out/gn" --version
    exit 0
  fi
fi

rm -rf "$destination"
git clone -q https://gn.googlesource.com/gn "$destination"
git -C "$destination" checkout -q --detach "$revision"

current=$(git -C "$destination" rev-parse HEAD)
if [ "$current" != "$revision" ]; then
  printf 'unexpected GN revision: %s\n' "$current" >&2
  exit 1
fi

python3 "$destination/build/gen.py"
ninja -C "$destination/out" gn
"$destination/out/gn" --version
