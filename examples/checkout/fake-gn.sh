#!/bin/sh
set -eu

case "${1:-}" in
  --version)
    printf '%s\n' 'chromifer-fixture-gn'
    ;;
  args)
    exit 0
    ;;
  ls)
    printf '%s\n' '//app:browser' '//base:base'
    ;;
  desc)
    case "${3:-}" in
      '//app:browser')
        printf '%s\n' '{"//app:browser":{"type":"executable","toolchain":"//build/toolchain/linux:clang_x64","sources":["//app/main.cc"],"deps":["//base:base"],"testonly":false}}'
        ;;
      '//base:base')
        printf '%s\n' '{"//base:base":{"type":"source_set","toolchain":"//build/toolchain/linux:clang_x64","sources":["//base/base.cc"],"deps":[],"testonly":false}}'
        ;;
      *)
        exit 3
        ;;
    esac
    ;;
  *)
    exit 2
    ;;
esac
