#!/usr/bin/env bash
set -euo pipefail

CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"

if ! command -v "$CLANG_FORMAT" >/dev/null 2>&1; then
  echo "Error: '$CLANG_FORMAT' was not found in PATH." >&2
  echo "Install clang-format or set CLANG_FORMAT, for example:" >&2
  echo "  CLANG_FORMAT=clang-format-18 ./scripts/format.sh" >&2
  exit 1
fi

echo "Using: $("$CLANG_FORMAT" --version)"
echo "Formatting C/C++/Arduino sources..."

git ls-files -z -- \
  '*.c' '*.cc' '*.cpp' '*.cxx' \
  '*.h' '*.hh' '*.hpp' '*.hxx' \
  '*.ino' \
  | xargs -0 -r "$CLANG_FORMAT" -i

echo "Formatting complete."