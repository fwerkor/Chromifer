#!/bin/sh
set -eu

chromium_revision=008cdad85f0721c89b42ef4dcaabcee615482609
depot_tools_revision=0a0574531b3b3ac9d478141874f2dab24cad64ab

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <workspace> [--update]" >&2
  exit 2
fi

workspace=$1
mode=${2:---check}
case "$mode" in
  --check|--update) ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
source_root=$workspace/src
depot_tools=$workspace/depot_tools
contract=examples/integration/chromium-native.json
checkout_contract=examples/integration/chromium-native-checkout.json
checkout_lock=examples/integration/chromium-native-checkout-lock.json
report=examples/integration/chromium-native-report.json
args_file=examples/integration/chromium-native.args.gn
summary=$(mktemp)
report_candidate=$(mktemp)
trap 'rm -f "$summary" "$report_candidate"' EXIT HUP INT TERM

cd "$repo_root"

test "$(git -C "$source_root" rev-parse HEAD)" = "$chromium_revision"
test "$(git -C "$depot_tools" rev-parse HEAD)" = "$depot_tools_revision"
if [ -n "$(git -C "$source_root" status --porcelain --untracked-files=all)" ]; then
  echo "Chromium source checkout is dirty" >&2
  exit 1
fi

mkdir -p "$source_root/out/ChromiferNative"
if [ "$mode" = "--update" ]; then
  cp "$args_file" "$source_root/out/ChromiferNative/args.gn"
else
  cmp "$args_file" "$source_root/out/ChromiferNative/args.gn"
fi

python3 "$source_root/build/util/lastchange.py" \
  -o "$source_root/build/util/LASTCHANGE" \
  --source-dir "$source_root"

cargo run --locked -q -p chromifer -- run-gn-integration \
  . \
  "$source_root" \
  "$contract" \
  --gn "$source_root/buildtools/linux64/gn" \
  --ninja "$source_root/third_party/ninja/ninja" \
  --json > "$summary"

if [ "$mode" = "--update" ]; then
  cargo run --locked -q -p chromifer -- audit-checkout \
    "$workspace" \
    "$checkout_contract" \
    "$checkout_lock" \
    --force >/dev/null
else
  cargo run --locked -q -p chromifer -- audit-checkout \
    "$workspace" \
    "$checkout_contract" \
    "$checkout_lock" \
    --check >/dev/null
fi

CHROMIFER_NATIVE_SUMMARY=$summary \
CHROMIFER_NATIVE_REPORT=$report_candidate \
CHROMIFER_NATIVE_WORKSPACE=$workspace \
CHROMIFER_NATIVE_CHROMIUM_REVISION=$chromium_revision \
CHROMIFER_NATIVE_DEPOT_TOOLS_REVISION=$depot_tools_revision \
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

repo = Path.cwd()
workspace = Path(os.environ["CHROMIFER_NATIVE_WORKSPACE"]).resolve()
source = workspace / "src"
summary = json.loads(Path(os.environ["CHROMIFER_NATIVE_SUMMARY"]).read_text())
lock_path = repo / "examples/integration/chromium-native-checkout-lock.json"
lock = json.loads(lock_path.read_text())
integration_contract_path = repo / "examples/integration/chromium-native.json"
integration_contract = json.loads(integration_contract_path.read_text())

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def repository_input(path: str) -> dict:
    source_path = repo / path
    content = source_path.read_bytes()
    return {
        "path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
    }

package_root = integration_contract["package_root"]
build_provenance_path = integration_contract["build_provenance"]
c_abi_provenance_path = integration_contract["c_abi_provenance"]
build_provenance = json.loads((repo / build_provenance_path).read_text())
c_abi_provenance = json.loads((repo / c_abi_provenance_path).read_text())
repository_paths = {
    "examples/integration/chromium-native.json",
    build_provenance_path,
    c_abi_provenance_path,
    f"{package_root}/BUILD.gn",
    f"{package_root}/{build_provenance['crate_root']}",
    f"{package_root}/{integration_contract['endpoint_source']}",
    f"{package_root}/{c_abi_provenance['contract_path']}",
    f"{package_root}/{c_abi_provenance['header_path']}",
}
repository_paths.update(f"{package_root}/{path}" for path in build_provenance["sources"])
repository_paths.update(
    f"{package_root}/{path}" for path in build_provenance["consumer"]["sources"]
)
repository_paths.update(build_provenance["consumer"]["required_headers"])
repository_paths.update(
    f"{package_root}/{source['source']}" for source in c_abi_provenance["sources"]
)

expected_tool_paths = {
    "gn": "buildtools/linux64/gn",
    "ninja": "third_party/ninja/ninja",
    "rustc": "third_party/rust-toolchain/bin/rustc",
}
tools = {}
for name, relative in expected_tool_paths.items():
    identity = summary["tools"][name]
    expected = (source / relative).resolve()
    if Path(identity["resolved_path"]).resolve() != expected:
        raise SystemExit(f"{name} resolved outside the pinned Chromium checkout")
    tools[name] = {
        "path": relative,
        "sha256": identity["sha256"],
        "bytes": identity["bytes"],
        "version": identity["version"],
    }

gn_output = lock["gn_outputs"][0]
report = {
    "schema_version": 1,
    "chromium_revision": os.environ["CHROMIFER_NATIVE_CHROMIUM_REVISION"],
    "depot_tools_revision": os.environ["CHROMIFER_NATIVE_DEPOT_TOOLS_REVISION"],
    "integration_contract_sha256": digest(repo / "examples/integration/chromium-native.json"),
    "checkout_contract_sha256": digest(repo / "examples/integration/chromium-native-checkout.json"),
    "checkout_lock_sha256": digest(lock_path),
    "sparse_paths_sha256": digest(repo / "examples/integration/chromium-native-sparse-paths.txt"),
    "gn_args_sha256": digest(repo / "examples/integration/chromium-native.args.gn"),
    "source": {
        "clean": lock["source"]["clean"],
        "status_sha256": lock["source"]["status_sha256"],
        "submodule_status_sha256": lock["source"]["submodule_status_sha256"],
    },
    "repository_inputs": [repository_input(path) for path in sorted(repository_paths)],
    "gn_output": {
        "id": gn_output["id"],
        "default_toolchain": gn_output["default_toolchain"],
        "target_count": gn_output["target_count"],
        "project_semantic_sha256": gn_output["project_semantic_sha256"],
        "args_sha256": gn_output["args"]["sha256"],
        "build_sha256": gn_output["build"]["sha256"],
        "required_targets": gn_output["required_targets"],
    },
    "endpoint": {
        "target": summary["endpoint_target"],
        "sha256": summary["endpoint_sha256"],
        "bytes": summary["endpoint_bytes"],
        "exit_code": summary["endpoint_exit_code"],
    },
    "tools": tools,
}
Path(os.environ["CHROMIFER_NATIVE_REPORT"]).write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)
PY

if [ "$mode" = "--update" ]; then
  mv "$report_candidate" "$report"
else
  cmp "$report" "$report_candidate"
fi

python3 - "$report" <<'PY'
import json
import sys
from pathlib import Path
report = json.loads(Path(sys.argv[1]).read_text())
print(
    "Chromium native endpoint:",
    report["endpoint"]["sha256"],
    report["endpoint"]["bytes"],
    report["tools"]["rustc"]["version"],
)
PY
