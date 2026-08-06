# Mojo boundary contracts

Chromifer generates Chromium `mojom()` targets from an explicit multi-target contract. The contract defines source ownership, external import mappings, visibility, and parser dependencies. Chromifer derives local target dependencies from Mojom imports and enables Rust bindings for every generated target.

## Contract format

A schema version 1 contract is JSON:

```json
{
  "schema_version": 1,
  "gn_package_path": "//services/example/mojom",
  "targets": [
    {
      "name": "common",
      "sources": ["common.mojom"],
      "visibility": ["//services/example:*"]
    },
    {
      "name": "service",
      "sources": ["service.mojom"],
      "external_imports": {
        "mojo/public/mojom/base/time.mojom": "//mojo/public/mojom/base"
      },
      "parser_deps": ["//services/example:custom_parser_data"],
      "visibility": ["//services/example:*"]
    }
  ]
}
```

Each `.mojom` source belongs to exactly one target. Target names use GN identifier syntax and must not collide with any target generated internally by Chromium's Mojom templates, including Rust, parser, metadata, generator, shared, headers, JavaScript, Java, TypeScript, or Mojolpm targets.

## Import resolution

Mojom imports are repository-root paths:

```mojom
import "services/example/mojom/common.mojom";
import "mojo/public/mojom/base/time.mojom";
```

Chromifer resolves imports in three ways:

1. An import owned by another target in the same contract becomes a local `public_deps` label such as `:common`.
2. An import owned by the current target is recorded but needs no target dependency.
3. Every external import requires an exact `external_imports` entry mapping the import path to an absolute GN label.

Generation fails for missing or unused external mappings. A file that exists under the current package but is not assigned to a target is rejected instead of being disguised as an external dependency. Self-imports and cycles between local targets are also rejected.

Absolute labels whose explicit target equals the final path component are normalized to GN's canonical form. For example, `//mojo/public/mojom/base:base` becomes `//mojo/public/mojom/base`.

## Generate and verify

```bash
cargo run -p chromifer -- generate-mojo \
  path/to/mojom-package \
  path/to/mojom-package/mojo.json \
  path/to/mojom-package/BUILD.gn
```

The command writes:

```text
BUILD.gn
chromifer-mojo.json
```

Each generated target has this shape:

```gn
mojom("service") {
  sources = [ "service.mojom" ]
  public_deps = [
    ":common",
    "//mojo/public/mojom/base",
  ]
  generate_rust = true
  visibility = [ "//services/example:*" ]
}
```

Chromium therefore exposes the normal C++ target and the corresponding `<target>_rust` target. The Mojom template propagates Mojom dependencies to the matching Rust binding targets.

Generated files should be committed. CI verifies drift without modifying them:

```bash
cargo run -p chromifer -- generate-mojo \
  path/to/mojom-package \
  path/to/mojom-package/mojo.json \
  path/to/mojom-package/BUILD.gn \
  --check
```

## Provenance

`chromifer-mojo.json` records:

- SHA-256 of the contract and generated BUILD.gn;
- package and output paths;
- C++ and Rust labels for every target;
- every Mojom source and its SHA-256;
- module declarations;
- top-level interface, struct, union, and enum declarations with source lines;
- every import with source line, local/external classification, and resolved dependency label;
- normalized public dependencies, parser dependencies, visibility, and `testonly` state.

The declaration scanner ignores comments and string contents, requires import terminators, and checks module syntax and brace balance. Nested declarations are intentionally excluded from the top-level inventory so identically named nested enums in separate interfaces do not become false duplicate declarations.

## Scope and limitations

Chromifer validates the target graph and the Mojom surface needed to derive it. It is not a replacement for Chromium's Mojom parser or generators. The real Chromium build remains authoritative for complete IDL grammar, type resolution, typemaps, generated C++/Rust compilation, and runtime interoperability.

The current contract supports:

- multiple Mojom targets in one package;
- C++ and Rust binding generation;
- local and explicitly mapped external imports;
- parser dependencies, visibility, and `testonly`;
- deterministic provenance and drift detection.

It does not yet model variants, Rust typemaps, C++ typemaps, Java/JavaScript/TypeScript generation options, feature-conditional targets, or runtime endpoint ownership contracts.

See `examples/mojo-bridge` for a two-target example with a local import and a Chromium `mojo_base` dependency.
