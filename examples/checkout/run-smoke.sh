#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
fixture_root="$repo_root/examples/checkout"
temp_root=$(mktemp -d "${TMPDIR:-/tmp}/chromifer-checkout-smoke.XXXXXX")
trap 'rm -rf "$temp_root"' EXIT INT TERM

workspace="$temp_root/workspace"
source_root="$workspace/src"
mkdir -p "$source_root/out/Default"
cp -a "$fixture_root/source/." "$source_root/"

(
  cd "$source_root"
  git init -q
  git add .
  GIT_AUTHOR_DATE=2000-01-01T00:00:00Z \
  GIT_COMMITTER_DATE=2000-01-01T00:00:00Z \
    git -c user.name='Chromifer Fixture' \
        -c user.email='chromifer@example.invalid' \
        -c commit.gpgsign=false \
        commit -qm fixture
)
revision=$(git -C "$source_root" rev-parse HEAD)

printf '%s\n' 'is_debug = false' > "$source_root/out/Default/args.gn"
printf '%s\n' 'rule noop' '  command = true' > "$source_root/out/Default/build.ninja"
printf '%s\n' "solutions = [{ 'name': 'src' }]" > "$workspace/.gclient"
printf "entries = {r'%s': 'src'}\n" "$source_root" > "$workspace/.gclient_entries"

python3 - "$fixture_root/project.template.json" "$source_root/out/Default/project.json" "$source_root" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
Path(sys.argv[2]).write_text(source.replace("@SOURCE_ROOT@", sys.argv[3]))
PY

python3 - "$fixture_root/contract.template.json" "$workspace/checkout.json" "$revision" <<'PY'
from pathlib import Path
import sys
source = Path(sys.argv[1]).read_text()
Path(sys.argv[2]).write_text(source.replace("@REVISION@", sys.argv[3]))
PY

lock="$temp_root/checkout-lock.json"
cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- audit-checkout \
  "$workspace" \
  "$workspace/checkout.json" \
  "$lock" \
  --gn "$fixture_root/fake-gn.sh"

cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- audit-checkout \
  "$workspace" \
  "$workspace/checkout.json" \
  "$lock" \
  --gn "$fixture_root/fake-gn.sh" \
  --check

python3 - "$lock" "$temp_root" "$revision" <<'PY'
import json
from pathlib import Path
import sys
report = json.loads(Path(sys.argv[1]).read_text())
raw = Path(sys.argv[1]).read_text()
assert report["source"]["revision"] == sys.argv[3]
assert report["source"]["clean"] is True
assert len(report["metadata_files"]) == 3
assert len(report["gn_outputs"]) == 1
output = report["gn_outputs"][0]
assert output["build_dir"] == "//out/Default/"
assert output["default_toolchain"] == "//build/toolchain/linux:clang_x64"
assert [target["label"] for target in output["required_targets"]] == [
    "//app:browser",
    "//base:base",
]
assert sys.argv[2] not in raw
print(f"checkout smoke: {report['source']['revision']} {output['project_semantic_sha256']}")
PY

cat > "$temp_root/base.toml" <<'EOF'
schema_version = 1

[project]
name = "checkout-fixture"
upstream = "fixture"
baseline = "fixture"

[[targets]]
id = "linux"
description = "Linux fixture"
required = true

[[modules]]
id = "browser_fixture"
path = "src"
owner = "fixture"
state = "legacy_cpp"
EOF

python3 - "$temp_root/gates.json" "$repo_root" <<'PY'
import json
from pathlib import Path
import sys
contract = {
    "schema_version": 1,
    "runner": {
        "program": "cargo",
        "args": [
            "run",
            "--manifest-path",
            str(Path(sys.argv[2]) / "Cargo.toml"),
            "-q",
            "-p",
            "chromifer",
            "--",
        ],
    },
    "checks": [
        {
            "kind": "checkout",
            "id": "checkout-current",
            "workspace_root": "workspace",
            "contract": "workspace/checkout.json",
            "report": "checkout-lock.json",
            "modules": ["browser_fixture"],
            "targets": ["linux"],
        }
    ],
}
Path(sys.argv[1]).write_text(json.dumps(contract, indent=2) + "\n")
PY

cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- derive-gates \
  "$temp_root" \
  "$temp_root/base.toml" \
  "$temp_root/gates.json" \
  "$temp_root/generated.toml"

evidence_root="$temp_root/evidence"
cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- run-gates \
  "$temp_root/generated.toml" \
  "$temp_root" \
  "$evidence_root" \
  --attest-executables \
  --json > "$temp_root/run.json"
evidence=$(python3 - "$temp_root/run.json" <<'PY'
import json
from pathlib import Path
import sys
run = json.loads(Path(sys.argv[1]).read_text())
assert run["bundle"]["passed"] is True
assert [gate["gate"] for gate in run["bundle"]["gates"]] == ["checkout-current"]
assert run["bundle"]["gates"][0]["executable"] is not None
print(run["path"])
PY
)
cargo run -q -p chromifer --manifest-path "$repo_root/Cargo.toml" -- verify-evidence \
  "$temp_root/generated.toml" \
  "$evidence" \
  "$evidence_root"
