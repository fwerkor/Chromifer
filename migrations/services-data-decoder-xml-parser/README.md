# data_decoder XmlParser Rust successor (WIP)

This directory tracks the current M3 successor for Chromium's production `data_decoder.mojom.XmlParser` at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The current design is Rust-native at the production Mojo boundary. `use_rust_data_decoder_xml_parser` defaults to `enable_rust`. With the flag enabled, `DataDecoderService` transfers the `XmlParser` receiver to `services/data_decoder/xml/xml_parser_mojo.rs` once; parsing, tree construction, `mojo_base.mojom.Value` construction, and the response all stay in Rust. The candidate `//services/data_decoder:xml_parser_impl` dependency graph explicitly contains neither libxml nor the pre-existing C++ XML DOM/CXX builder path. Setting the flag to `false` restores the pinned upstream `xml_parser.cc` implementation and its libxml dependencies.

Current Linux parity is 46/46 in both configurations. The focused suite contains the 25 legacy production `XmlParser` tests plus 21 Rust/parser compatibility cases. Valid Mojom-string cases call the real candidate or fallback receiver through a Mojo pipe. Legacy invalid-byte `std::string` cases remain parser-layer regressions in the Rust configuration because Mojom `string` itself requires UTF-8. `WhitespaceBehavior::kPreserveSignificant`, legacy error categories, text/CDATA behavior, attributes, namespaces, and explicit namespace redeclarations are covered.

Explicit namespace redeclarations required a small Chromium patch to the already-patched `xml-v1` crate: `0005-Expose-element-local-namespace-declarations.patch`. It exposes the current `NamespaceStack` layer through `EventReader` without changing the cumulative namespace carried by `XmlEvent::StartElement`. `gnrt vendor --force 'xml*'` reproduced identical patched sources, so this vendor change is rebuildable rather than an ad-hoc edit.

The direct Rust response also exposed a generic Rust Mojo limitation: recursive Mojom types such as `mojo_base.mojom.Value` previously caused infinite recursion while constructing `MojomWireType`. The patch adds lazy recursive wire-type references to `mojom_value_parser`; the real XmlParser suite now exercises nested dictionary/list `Value` responses end-to-end across Rust→C++ Mojo. A standalone recursive `MojomParse` regression has also been added to the Rust parser tests.

The exact current Chromium patch SHA-256 is `a47d90b659de742366946c722e6dc26e9545b219252b143c896c57cc74444731`.

A previous parity-green design routed the production Mojo implementation through Chromium's existing Rust XML parser and C++ DOM/CXX builder. Its strict exposure measurement failed badly (memory-unsafe LOC 187→460, production LOC 187→597, files 2→8), and that evidence remains in `evidence/linux-exposure-cxx-dom-adapter.json`. That architecture is superseded; the current exposure definition measures the actual direct-Rust production graph and will be recomputed without weakening the M3 gate.

Broader upstream regression, desktop portability, performance, and the new direct-Rust exposure measurement remain pending before M3 acceptance.
