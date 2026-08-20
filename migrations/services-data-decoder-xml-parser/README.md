# data_decoder XmlParser Rust successor (WIP)

This directory tracks the current M3 successor for Chromium's production `data_decoder.mojom.XmlParser` at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The current design is Rust-native at the production Mojo boundary. `use_rust_data_decoder_xml_parser` defaults to `enable_rust`. With the flag enabled, `DataDecoderService` transfers the `XmlParser` receiver to `services/data_decoder/xml/xml_parser_mojo.rs` once; parsing, tree construction, `mojo_base.mojom.Value` construction, and the response all stay in Rust. The candidate `//services/data_decoder:xml_parser_impl` dependency graph explicitly contains neither libxml nor the pre-existing C++ XML DOM/CXX builder path. Setting the flag to `false` restores the pinned upstream `xml_parser.cc` implementation and its libxml dependencies.

Current Linux parity is 46/46 in both configurations. The focused suite contains the 25 legacy production `XmlParser` tests plus 21 Rust/parser compatibility cases. Valid Mojom-string cases call the real candidate or fallback receiver through a Mojo pipe. Legacy invalid-byte `std::string` cases remain parser-layer regressions in the Rust configuration because Mojom `string` itself requires UTF-8. `WhitespaceBehavior::kPreserveSignificant`, legacy error categories, text/CDATA behavior, attributes, namespaces, and explicit namespace redeclarations are covered.

Explicit namespace redeclarations required a small Chromium patch to the already-patched `xml-v1` crate: `0005-Expose-element-local-namespace-declarations.patch`. It exposes the current `NamespaceStack` layer through `EventReader` without changing the cumulative namespace carried by `XmlEvent::StartElement`. `gnrt vendor --force 'xml*'` reproduced identical patched sources, so this vendor change is rebuildable rather than an ad-hoc edit.

The direct Rust response also exposed a generic Rust Mojo limitation: recursive Mojom types such as `mojo_base.mojom.Value` previously caused infinite recursion while constructing `MojomWireType`. The patch adds lazy recursive wire-type references to `mojom_value_parser`; the real XmlParser suite now exercises nested dictionary/list `Value` responses end-to-end across Rust→C++ Mojo. A standalone recursive `MojomParse` regression has also been added to the Rust parser tests.

The exact current Chromium patch SHA-256 is `8ceed0f84793172b147273697bcb0dac93224a6a7b1c47d922a0c2a4f0076ef3`.

A previous parity-green design routed the production Mojo implementation through Chromium's existing Rust XML parser and C++ DOM/CXX builder. Its strict exposure measurement failed badly (memory-unsafe LOC 187→460, production LOC 187→597, files 2→8), and that evidence remains in `evidence/linux-exposure-cxx-dom-adapter.json`.

The direct-Rust design now passes the unchanged strict exposure gate. Against the pinned production baseline, authored memory-unsafe LOC drops 259→73, authored production LOC 259→244, active implementation files 3→2, branch points 23→20, and manual raw-pointer fields 1→0. The production `DataDecoderService` object also compiles with the shared `BindXmlParser` handoff; candidate GN dependencies exclude libxml and C++ XML DOM, while the rollback restores libxml and excludes the Rust receiver.

Broader upstream regression, desktop portability, and performance remain pending before full M3 acceptance.
