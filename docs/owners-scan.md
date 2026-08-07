# Chromium OWNERS hierarchy scan

`scan-owners` resolves repository ownership for every source listed in a Chromifer manifest and writes the provenance back into the manifest without replacing the existing architectural `owner` label.

```bash
cargo run -p chromifer -- scan-owners \
  chromium-boundaries.toml \
  /path/to/chromium/src \
  chromium-owned.toml
```

## Supported Chromium semantics

The scanner implements the ownership behavior used by Chromium's depot_tools parser:

- email addresses and `*` owner entries;
- inheritance from enclosing directories;
- global `set noparent`;
- `per-file <glob>=<directive>` rules with filename-only `*` and `?` globs;
- per-file `set noparent`, which suppresses both same-file global entries and parent inheritance for matching files;
- `file:<relative path>` includes;
- `file://<repository-relative path>` includes;
- nested includes and include-cycle detection;
- Gerrit cross-project includes such as `platform/system/core:main:/janitors/OWNERS`, retained as unresolved provenance rather than treated as local owners;
- inline and full-line comments.

Relative includes may contain `..` only while the normalized result remains inside the repository root.

## Manifest provenance

Each module receives an optional `ownership` section containing:

- union of nearest applicable `primary_owners`;
- union of all inherited `effective_owners`;
- owners common to every resolved source;
- all contributing OWNERS files;
- unresolved source paths;
- unresolved external include directives together with the local OWNERS file that declared them;
- whether source files have different primary-owner sets;
- per-source owners, provenance files, and inheritance stop location.

Example:

```toml
[modules.ownership]
primary_owners = ["network@chromium.org"]
effective_owners = ["network@chromium.org", "services@chromium.org"]
common_effective_owners = ["services@chromium.org"]
owner_files = ["services/OWNERS", "services/network/OWNERS"]
unresolved_includes = [
  { owner_file = "third_party/example/OWNERS", include = "other/project:main:/OWNERS" },
]
split_ownership = false

[[modules.ownership.sources]]
source = "services/network/network_context.cc"
primary_owners = ["network@chromium.org"]
effective_owners = ["network@chromium.org", "services@chromium.org"]
owner_files = ["services/OWNERS", "services/network/OWNERS"]
```

The pre-existing module `owner` remains a project-level architectural domain such as `browser-services`. It is not overwritten with an email address.

External Gerrit projects are intentionally not fetched during a source scan. Their include directives remain visible in the manifest, and candidate ranking treats that incomplete ownership graph as an audit concern rather than silently assuming the locally resolved owners are complete.

## Component aggregation

When ownership provenance exists, `rank-components` uses the sorted primary-owner set as its grouping key. This prevents two targets under the same directory and coarse architectural owner from being merged when Chromium's OWNERS hierarchy assigns them to different maintainers.

When no primary owner can be resolved, aggregation falls back to the manifest's original `owner` field.

## Limitations

The scanner resolves local approval ownership, not expertise, code review history, or actual team membership. `*` is retained literally. It does not query account directories, remote Gerrit projects, or determine whether an email is currently active.
