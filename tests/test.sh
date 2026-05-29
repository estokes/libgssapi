#!/usr/bin/env bash
# Run libgssapi's test suite against MIT (host), Heimdal (container), Apple
# GSS.framework (host, macOS), or both Linux impls.
#
# Usage:
#   tests/test.sh                  # host default: Apple on macOS, else MIT
#   tests/test.sh mit              # MIT on host
#   tests/test.sh apple            # Apple GSS.framework on host (macOS only)
#   tests/test.sh heimdal          # Heimdal in podman container
#   tests/test.sh all              # both Linux impls (MIT + Heimdal)
#
# Heimdal mode auto-builds the libgssapi-heimdal image on first run; the
# image is cached after that. Build artifacts live in target-heimdal/ to
# keep host (MIT) and container (Heimdal) builds from clobbering each other.

set -euo pipefail
cd "$(dirname "$0")/.."

run_mit() {
    echo "=== MIT (host) ==="
    cargo test --all-features --lib --tests -- --test-threads=1
}

run_apple() {
    echo "=== Apple GSS.framework (host) ==="
    # No optional features: Apple's GSS.framework backs none of them (iov,
    # localname, store need MIT/Heimdal functions; s4u is MIT-only). Enabling
    # any would be a compile error, so the default (empty) feature set is the
    # full surface Apple supports. The KDC is the system Heimdal (the TestKdc
    # fixture finds it automatically).
    cargo test --lib --tests -- --test-threads=1
}

run_heimdal() {
    echo "=== Heimdal (container) ==="
    podman build -q -t libgssapi-heimdal -f tests/docker/Dockerfile.heimdal tests/docker/ >/dev/null
    # Everything Heimdal supports, which is everything except s4u (s4u needs
    # gss_acquire_cred_impersonate_name / gss_store_cred_into, MIT-only). Not
    # --all-features (that includes s4u); features default to empty now, so
    # enable iov/localname/store explicitly.
    podman run --rm \
        -v "$PWD:/work" \
        -w /work \
        libgssapi-heimdal \
        cargo test --features iov,localname,store --lib --tests -- --test-threads=1
}

shell_heimdal() {
    echo "=== Heimdal (container) ==="
    podman build -q -t libgssapi-heimdal -f tests/docker/Dockerfile.heimdal tests/docker/ >/dev/null
    podman run --rm -it \
        -v "$PWD:/work" \
        -w /work \
        libgssapi-heimdal \
        bash
}

default_mode() {
    if [ "$(uname -s)" = "Darwin" ]; then echo apple; else echo mit; fi
}

case "${1:-$(default_mode)}" in
    mit)     run_mit ;;
    apple)   run_apple ;;
    heimdal) run_heimdal ;;
    heimdalshell) shell_heimdal ;;
    all)     run_mit; echo; run_heimdal ;;
    *)
        echo "Usage: $0 {mit|apple|heimdal|all}" >&2
        exit 1
        ;;
esac
