#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_root="$repo_root/examples/integration/gn-root"
out_dir="$source_root/out/ChromiferIntegration"

command -v gn >/dev/null
command -v ninja >/dev/null
command -v rustc >/dev/null

rm -rf "$out_dir"
rmdir "$source_root/examples" 2>/dev/null || true

summary=$(mktemp "${TMPDIR:-/tmp}/chromifer-integration.XXXXXX.json")
trap 'rm -f "$summary"' EXIT INT TERM

cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- run-gn-integration \
  "$repo_root" \
  "$source_root" \
  examples/integration/c-abi.json \
  --json > "$summary"

python3 - "$summary" "$source_root" <<'PY'
import json
from pathlib import Path
import sys

summary = json.loads(Path(sys.argv[1]).read_text())
source_root = Path(sys.argv[2])
assert summary["package"] == "chromifer-c-abi-example"
assert summary["root_target"] == "//examples/c-abi-bridge:integration"
assert summary["endpoint_target"] == "//examples/c-abi-bridge:c_abi_endpoint"
assert summary["target_count"] == 5
assert summary["endpoint_exit_code"] == 0
assert summary["endpoint_bytes"] > 0
assert len(summary["endpoint_sha256"]) == 64
assert summary["tools"]["gn"]["version"]
assert summary["tools"]["ninja"]["version"]
assert summary["tools"]["rustc"]["version"].startswith("rustc ")
assert Path(summary["endpoint_path"]).is_file()
assert not (source_root / "examples").exists()
assert not (source_root / "build/rust").exists()
print(
    "GN endpoint smoke:",
    summary["endpoint_sha256"],
    summary["endpoint_bytes"],
    summary["tools"]["gn"]["version"],
)
PY
