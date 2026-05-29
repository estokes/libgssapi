#!/usr/bin/env bash
# Run libgssapi's test suite against MIT (host), Heimdal (container), or both.
#
# Usage:
#   tests/test.sh                  # MIT on host
#   tests/test.sh heimdal          # Heimdal in podman container
#   tests/test.sh all              # both
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

run_heimdal() {
    echo "=== Heimdal (container) ==="
    podman build -q -t libgssapi-heimdal -f tests/docker/Dockerfile.heimdal tests/docker/ >/dev/null
    # Not --all-features: the s4u feature needs gss_acquire_cred_impersonate_name
    # / gss_store_cred_into, which Heimdal does not provide. Test the default
    # feature set (iov, localname, store), which is everything Heimdal supports.
    podman run --rm \
        -v "$PWD:/work" \
        -w /work \
        libgssapi-heimdal \
        cargo test --lib --tests -- --test-threads=1
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

case "${1:-mit}" in
    mit)     run_mit ;;
    heimdal) run_heimdal ;;
    heimdalshell) shell_heimdal ;;
    all)     run_mit; echo; run_heimdal ;;
    *)
        echo "Usage: $0 {mit|heimdal|all}" >&2
        exit 1
        ;;
esac
