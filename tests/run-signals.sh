#!/bin/sh
# Standalone runner: intentionally independent of the project's Makefile.
set -eu
cd "$(dirname "$0")/.."
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
"${CC:-cc}" -Iinclude -Wall -Wextra -g -fsanitize=address,undefined \
    -Wl,--wrap=prctl tests/signals.c src/handlesig.c -o "$test_dir/signals"
"$test_dir/signals"
