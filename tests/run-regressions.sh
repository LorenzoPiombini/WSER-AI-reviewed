#!/bin/sh
# Fresh, isolated test builds without modifying or installing the Makefile targets.
set -eu
cd "$(dirname "$0")/.."
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
for source in network request response monitor json load; do
    ${CC:-cc} -Iinclude -Wall -Wextra -g -O1 -fno-omit-frame-pointer \
        ${SANITIZERS:--fsanitize=address,undefined} \
        -c "src/$source.c" -o "$build_dir/$source.o"
done
for suite in regression infrastructure tls; do
    wrappers=
    if [ "$suite" = infrastructure ]; then
        wrappers=-Wl,--wrap=getuid,--wrap=socket,--wrap=bind,--wrap=listen,--wrap=connect,--wrap=accept4,--wrap=read
    fi
    ${CC:-cc} -Iinclude -Wall -Wextra -g -O1 -fno-omit-frame-pointer \
        ${SANITIZERS:--fsanitize=address,undefined} $wrappers \
        "tests/$suite.c" "$build_dir"/*.o -lcrypto -lssl -o "$build_dir/$suite"
done
${CC:-cc} -Iinclude -g ${SANITIZERS:--fsanitize=address,undefined} \
    json_parser_test.c "$build_dir/json.o" -o "$build_dir/json-tests"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$build_dir/key.pem" \
    -out "$build_dir/cert.pem" -subj /CN=localhost -days 1 2>/dev/null
"$build_dir/regression"
"$build_dir/infrastructure"
"$build_dir/json-tests"
"$build_dir/tls" "$build_dir/cert.pem" "$build_dir/key.pem"
