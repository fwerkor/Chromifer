# data_decoder XmlParser Rust successor (retired pilot)

This directory tracks the current M3 successor for Chromium's production `data_decoder.mojom.XmlParser` at upstream revision `04f9a8144d9b1701aa0b329b6000cf3299bbaf22`.

The current design is Rust-native at the production Mojo boundary. `use_rust_data_decoder_xml_parser` defaults to `enable_rust`. With the flag enabled, `DataDecoderService` transfers the `XmlParser` receiver to `services/data_decoder/xml/xml_parser_mojo.rs` once; parsing, tree construction, `mojo_base.mojom.Value` construction, and the response all stay in Rust. The candidate `//services/data_decoder:xml_parser_impl` dependency graph explicitly contains neither libxml nor the pre-existing C++ XML DOM/CXX builder path. Setting the flag to `false` restores the pinned upstream `xml_parser.cc` implementation and its libxml dependencies.

Current Linux parity is 46/46 in both configurations. The focused suite contains the 25 legacy production `XmlParser` tests plus 21 Rust/parser compatibility cases. Valid Mojom-string cases call the real candidate or fallback receiver through a Mojo pipe. Legacy invalid-byte `std::string` cases remain parser-layer regressions in the Rust configuration because Mojom `string` itself requires UTF-8. `WhitespaceBehavior::kPreserveSignificant`, legacy error categories, text/CDATA behavior, attributes, namespaces, and explicit namespace redeclarations are covered.

Explicit namespace redeclarations required a small Chromium patch to the already-patched `xml-v1` crate: `0005-Expose-element-local-namespace-declarations.patch`. It exposes the current `NamespaceStack` layer through `EventReader` without changing the cumulative namespace carried by `XmlEvent::StartElement`. `gnrt vendor --force 'xml*'` reproduced identical patched sources, so this vendor change is rebuildable rather than an ad-hoc edit.

The direct Rust response also exposed a generic Rust Mojo limitation: recursive Mojom types such as `mojo_base.mojom.Value` previously caused infinite recursion while constructing `MojomWireType`. The patch adds lazy recursive wire-type references to `mojom_value_parser`; the real XmlParser suite now exercises nested dictionary/list `Value` responses end-to-end across Rust→C++ Mojo. A standalone recursive `MojomParse` regression has also been added to the Rust parser tests.

The exact final Chromium patch SHA-256 is `4e4bbaa93e3c779bf6faacfd980f790f3b7cb1738e026d03694a083e6f50f7ba`.

A previous parity-green design routed the production Mojo implementation through Chromium's existing Rust XML parser and C++ DOM/CXX builder. Its strict exposure measurement failed badly (memory-unsafe LOC 187→460, production LOC 187→597, files 2→8), and that evidence remains in `evidence/linux-exposure-cxx-dom-adapter.json`.

The final optimized direct-Rust design still reduces authored memory-unsafe LOC from 259 to 73, active implementation files from 3 to 2, and manual raw-pointer fields from 1 to 0. However, after the serializer and parser optimizations needed for the performance gate, authored production LOC is 309 versus the 259-line baseline and structural branch points are 37 versus 23. Under the original strict maintenance policy this final implementation therefore fails maintenance-complexity acceptance; the gate is not weakened to accommodate the optimization.

The final release-mode performance run passes the unchanged gate across all four workloads. Across 15 paired samples of 1,000 in-process Mojo calls, candidate median regressions are -5.88% (small_xml), -19.61% (attributes_namespaces), -9.09% (mixed_text_cdata), and -4.28% (large_xml); p95 regressions are -4.04%, -9.19%, -5.56%, and -6.52%, respectively. The maximum median RSS regression is 749,568 bytes, within the 1 MiB budget. The measured candidate binary is SHA-256 25f54dc22d8813dfa4cb6b5538ecaba69f4c65204d197953e450458661978749.

Broader upstream regression and macOS/Windows parity remain pending. Because the final optimized implementation also fails the original maintenance-complexity gate, this pilot is retired rather than marked M3-complete.
