# data_decoder XmlParser Rust successor (WIP)

This directory tracks the M3 successor candidate that moves Chromium's production `data_decoder.mojom.XmlParser` off the legacy libxml implementation and onto Chromium's existing Rust XML parser at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The candidate adds `use_rust_data_decoder_xml_parser`, defaulting to `enable_rust`, and a source-separated `xml_parser_impl` target. The Rust configuration links the existing `services/data_decoder/xml` parser/DOM path and excludes libxml from the production XmlParser dependency graph. Setting the flag to `false` compiles an exact copy of the pinned upstream `xml_parser.cc` as `xml_parser_legacy.cc` and restores the libxml dependencies.

Compatibility work completed in this checkpoint:

- arbitrary non-UTF-8 `std::string` inputs are passed to Rust as bytes and fail safely instead of aborting at the CXX `rust::Str` boundary;
- `WhitespaceBehavior::kPreserveSignificant` is preserved;
- legacy error categories used by the existing Mojo contract are normalized from xml-rs diagnostics;
- whitespace-only `Characters` events follow legacy ignore-whitespace behavior;
- explicit namespace redeclarations are preserved, including declarations identical to an inherited mapping.

The last item required a small Chromium patch to the already-patched `xml-v1` crate: `0005-Expose-element-local-namespace-declarations.patch`. It exposes the current `NamespaceStack` layer through `EventReader` without changing the cumulative namespace carried by `XmlEvent::StartElement`. `gnrt vendor --force 'xml*'` was run successfully and reproduced identical patched source hashes.

Current Linux checkpoint:

- Rust production configuration: focused `XmlParserTest.*:XmlParserRsTest.*` suite passes 46/46.
- libxml rollback configuration: the same focused suite passes 46/46.
- Rust production `//services/data_decoder:xml_parser_impl` graph excludes `//third_party/libxml`.
- rollback source is `xml_parser_legacy.cc` and the rollback graph restores `libxml`, `libxml_utils`, and `xml_reader`.
- exact Chromium patch SHA-256: `cc5edd9df397fb92dccecea4b6065d120a6d9d83c7094383a75f0474a8bdc784`.

This remains a WIP checkpoint. Exposure/maintenance measurement, broader upstream regression, desktop portability, performance, and a full production build still need to be completed before it can satisfy M3.
