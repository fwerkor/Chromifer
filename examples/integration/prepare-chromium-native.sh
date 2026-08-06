#!/bin/sh
set -eu

chromium_revision=008cdad85f0721c89b42ef4dcaabcee615482609
depot_tools_revision=0a0574531b3b3ac9d478141874f2dab24cad64ab
chromium_remote=https://github.com/chromium/chromium.git
depot_tools_remote=https://chromium.googlesource.com/chromium/tools/depot_tools.git

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <workspace> [--full]" >&2
  exit 2
fi

materialization=${2:---sparse}
case "$materialization" in
  --sparse|--full) ;;
  *)
    echo "unknown materialization mode: $materialization" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
workspace=$1
source_root=$workspace/src
depot_tools=$workspace/depot_tools
sparse_paths=$repo_root/examples/integration/chromium-native-sparse-paths.txt
args_file=$repo_root/examples/integration/chromium-native.args.gn
jobs=${CHROMIFER_GCLIENT_JOBS:-16}

for program in git python3; do
  command -v "$program" >/dev/null 2>&1 || {
    echo "missing required program: $program" >&2
    exit 1
  }
done

mkdir -p "$workspace"

prepare_repository() {
  directory=$1
  remote=$2
  revision=$3

  if [ ! -d "$directory/.git" ]; then
    mkdir -p "$directory"
    git -C "$directory" init -q
    git -C "$directory" remote add origin "$remote"
  fi

  if [ -n "$(git -C "$directory" status --porcelain --untracked-files=all)" ]; then
    echo "refusing to replace dirty repository: $directory" >&2
    exit 1
  fi

  git -C "$directory" fetch --filter=blob:none --depth 1 origin "$revision"
  git -C "$directory" checkout -q --detach FETCH_HEAD
  test "$(git -C "$directory" rev-parse HEAD)" = "$revision"
}

prepare_repository "$depot_tools" "$depot_tools_remote" "$depot_tools_revision"

if [ ! -d "$source_root/.git" ]; then
  mkdir -p "$source_root"
  git -C "$source_root" init -q
  git -C "$source_root" remote add origin "$chromium_remote"
  git -C "$source_root" fetch --filter=blob:none --depth 1 origin "$chromium_revision"
  git -C "$source_root" sparse-checkout init --cone
  # shellcheck disable=SC2046
  git -C "$source_root" sparse-checkout set $(cat "$sparse_paths")
  git -C "$source_root" checkout -q --detach FETCH_HEAD
else
  if [ -n "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]; then
    echo "refusing to replace dirty Chromium source: $source_root" >&2
    exit 1
  fi
  git -C "$source_root" fetch --filter=blob:none --depth 1 origin "$chromium_revision"
  git -C "$source_root" checkout -q --detach FETCH_HEAD
  git -C "$source_root" sparse-checkout init --cone
  # shellcheck disable=SC2046
  git -C "$source_root" sparse-checkout set $(cat "$sparse_paths")
fi

test "$(git -C "$source_root" rev-parse HEAD)" = "$chromium_revision"
printf '%s\n' "$chromium_revision" > "$workspace/PINNED_REVISION"
cat > "$workspace/.gclient" <<EOF
solutions = [
  {
    "name": "src",
    "url": "$chromium_remote",
    "deps_file": "DEPS",
    "managed": False,
    "custom_deps": {},
    "custom_vars": {},
    "safesync_url": "",
  },
]
target_os = []
EOF

PATH="$depot_tools:$PATH"
export PATH
export DEPOT_TOOLS_UPDATE=0
export GCLIENT_SUPPRESS_GIT_VERSION_WARNING=1

gclient sync \
  --no-history \
  --nohooks \
  --revision "src@$chromium_revision" \
  --jobs "$jobs"

test "$(git -C "$source_root" rev-parse HEAD)" = "$chromium_revision"
if [ "$materialization" = "--full" ]; then
  git -C "$source_root" sparse-checkout disable
fi
python3 "$source_root/build/util/lastchange.py" \
  -o "$source_root/build/util/LASTCHANGE" \
  --source-dir "$source_root"

mkdir -p "$source_root/out/ChromiferNative"
cp "$args_file" "$source_root/out/ChromiferNative/args.gn"

for executable in \
  "$source_root/buildtools/linux64/gn" \
  "$source_root/third_party/ninja/ninja" \
  "$source_root/third_party/rust-toolchain/bin/rustc"; do
  test -x "$executable" || {
    echo "missing native Chromium executable: $executable" >&2
    exit 1
  }
done

printf 'Chromium revision: %s\n' "$chromium_revision"
printf 'depot_tools revision: %s\n' "$depot_tools_revision"
printf 'source materialization: %s\n' "${materialization#--}"
printf 'GN: %s\n' "$("$source_root/buildtools/linux64/gn" --version)"
printf 'Ninja: %s\n' "$("$source_root/third_party/ninja/ninja" --version)"
printf 'Rustc: %s\n' "$("$source_root/third_party/rust-toolchain/bin/rustc" --version)"
