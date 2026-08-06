#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INTEGRATION = ROOT / "examples" / "integration"


def read_json(name: str) -> dict:
    return json.loads((INTEGRATION / name).read_text())


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    report = read_json("chromium-native-report.json")
    integration_contract = read_json("chromium-native.json")
    checkout_contract = read_json("chromium-native-checkout.json")
    checkout_lock = read_json("chromium-native-checkout-lock.json")

    require(report["schema_version"] == 1, "unsupported native report schema")
    require(integration_contract["schema_version"] == 1, "unexpected integration contract schema")
    require(checkout_contract["schema_version"] == 1, "unexpected checkout contract schema")
    require(checkout_lock["schema_version"] == 1, "unexpected checkout lock schema")

    expected_digests = {
        "integration_contract_sha256": INTEGRATION / "chromium-native.json",
        "checkout_contract_sha256": INTEGRATION / "chromium-native-checkout.json",
        "checkout_lock_sha256": INTEGRATION / "chromium-native-checkout-lock.json",
        "sparse_paths_sha256": INTEGRATION / "chromium-native-sparse-paths.txt",
        "gn_args_sha256": INTEGRATION / "chromium-native.args.gn",
    }
    for field, path in expected_digests.items():
        require(report[field] == sha256(path), f"stale {field}")

    checkout_contract_digest = sha256(INTEGRATION / "chromium-native-checkout.json")
    require(
        checkout_lock["contract_sha256"] == checkout_contract_digest,
        "checkout lock was derived from different contract bytes",
    )
    require(
        report["chromium_revision"] == checkout_contract["revision"] == checkout_lock["source"]["revision"],
        "Chromium revision mismatch",
    )
    require(checkout_lock["source"]["clean"], "native source lock is not clean")
    require(report["source"]["clean"], "native report source is not clean")
    for field in ("status_sha256", "submodule_status_sha256"):
        require(
            report["source"][field] == checkout_lock["source"][field],
            f"source {field} mismatch",
        )

    require(integration_contract["rust_template"] == "existing", "native contract does not use existing template")
    native_rustc = integration_contract.get("native_rustc")
    require(isinstance(native_rustc, str), "native contract does not declare native_rustc")
    require(native_rustc in integration_contract["source_inputs"], "native_rustc is not a hashed source input")
    require(
        "build/rust/rust_static_library.gni" in integration_contract["source_inputs"],
        "native Rust template is not a hashed source input",
    )

    package_root = integration_contract["package_root"]
    build_provenance_path = integration_contract["build_provenance"]
    c_abi_provenance_path = integration_contract["c_abi_provenance"]
    build_provenance = json.loads((ROOT / build_provenance_path).read_text())
    c_abi_provenance = json.loads((ROOT / c_abi_provenance_path).read_text())
    expected_repository_paths = {
        "examples/integration/chromium-native.json",
        build_provenance_path,
        c_abi_provenance_path,
        f"{package_root}/BUILD.gn",
        f"{package_root}/{build_provenance['crate_root']}",
        f"{package_root}/{integration_contract['endpoint_source']}",
        f"{package_root}/{c_abi_provenance['contract_path']}",
        f"{package_root}/{c_abi_provenance['header_path']}",
    }
    expected_repository_paths.update(
        f"{package_root}/{path}" for path in build_provenance["sources"]
    )
    expected_repository_paths.update(
        f"{package_root}/{path}" for path in build_provenance["consumer"]["sources"]
    )
    expected_repository_paths.update(build_provenance["consumer"]["required_headers"])
    expected_repository_paths.update(
        f"{package_root}/{source['source']}" for source in c_abi_provenance["sources"]
    )
    reported_inputs = {entry["path"]: entry for entry in report["repository_inputs"]}
    require(
        set(reported_inputs) == expected_repository_paths,
        "native report repository input set differs from provenance",
    )
    for path, entry in reported_inputs.items():
        source = ROOT / path
        require(entry["sha256"] == sha256(source), f"stale repository input digest: {path}")
        require(entry["bytes"] == source.stat().st_size, f"stale repository input size: {path}")

    require(len(checkout_lock["gn_outputs"]) == 1, "native lock must contain one GN output")
    locked_output = checkout_lock["gn_outputs"][0]
    reported_output = report["gn_output"]
    for field in ("id", "default_toolchain", "target_count", "project_semantic_sha256"):
        require(reported_output[field] == locked_output[field], f"GN output {field} mismatch")
    require(reported_output["args_sha256"] == locked_output["args"]["sha256"], "GN args digest mismatch")
    require(reported_output["build_sha256"] == locked_output["build"]["sha256"], "Ninja graph digest mismatch")
    require(reported_output["required_targets"] == locked_output["required_targets"], "required target semantics mismatch")
    require(report["gn_args_sha256"] == locked_output["args"]["sha256"], "committed args do not match checkout lock")

    required_labels = {target["label"] for target in locked_output["required_targets"]}
    require(report["endpoint"]["target"] in required_labels, "endpoint target is not locked")
    require(report["endpoint"]["exit_code"] == 0, "native endpoint did not pass")
    require(report["endpoint"]["bytes"] > 0, "native endpoint is empty")
    require(len(report["endpoint"]["sha256"]) == 64, "invalid endpoint digest")

    metadata = {entry["path"]: entry for entry in checkout_lock["metadata_files"]}
    for name, tool in report["tools"].items():
        locked_path = f"src/{tool['path']}"
        require(locked_path in metadata, f"{name} is not present in checkout metadata")
        require(tool["sha256"] == metadata[locked_path]["sha256"], f"{name} digest mismatch")
        require(tool["bytes"] == metadata[locked_path]["bytes"], f"{name} byte count mismatch")
        require(tool["version"], f"{name} version is empty")

    require(len(report["depot_tools_revision"]) == 40, "invalid depot_tools revision")
    print(
        "verified Chromium native report:",
        report["chromium_revision"],
        report["endpoint"]["sha256"],
        report["tools"]["rustc"]["version"],
    )


if __name__ == "__main__":
    main()
