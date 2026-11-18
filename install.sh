#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORCE_BUILD=0

for arg in "$@"; do
  case "$arg" in
    --build)
      FORCE_BUILD=1
      ;;
    -h|--help)
      cat << 'EOF'
Usage: ./install.sh [--build]

Installs tloc-explain without external downloads or network dependencies:
  - Default: installs the bundled static x86_64-unknown-linux-musl binary (./tloc-explain).
  - --build: compiles offline from the bundled ./vendor crates via cargo build --release --offline.

Destination:
  - root user:     /usr/local/bin/tloc-explain
  - non-root user: ~/.local/bin/tloc-explain
EOF
      exit 0
      ;;
    *)
      echo "Unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

if [ "$(id -u)" -eq 0 ]; then
  DEST_DIR="/usr/local/bin"
else
  DEST_DIR="${HOME}/.local/bin"
fi
mkdir -p "${DEST_DIR}"

BIN_SRC="${REPO_DIR}/tloc-explain"

if [ "${FORCE_BUILD}" -eq 1 ] || [ ! -x "${BIN_SRC}" ]; then
  if ! command -v cargo >/dev/null 2>&1; then
    for candidate in "${HOME}/.cargo/bin" "/root/.cargo/bin"; do
      if [ -x "${candidate}/cargo" ]; then
        export PATH="${candidate}:${PATH}"
        break
      fi
    done
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "Error: cargo not found and no bundled ./tloc-explain binary present." >&2
    exit 1
  fi

  BUILD_TMP="${HOME}/.cache/tloc-explain/build"
  mkdir -p "${BUILD_TMP}"
  chmod 0700 "${HOME}/.cache/tloc-explain" "${BUILD_TMP}" 2>/dev/null || true
  export TMPDIR="${BUILD_TMP}"

  echo "[*] Building tloc-explain offline from vendored crates in ${REPO_DIR}/vendor..."
  if command -v rustup >/dev/null 2>&1 && rustup target list --installed 2>/dev/null | grep -qx "x86_64-unknown-linux-musl"; then
    (cd "${REPO_DIR}" && CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}" cargo build --release --target x86_64-unknown-linux-musl --offline)
    BIN_SRC="${REPO_DIR}/target/x86_64-unknown-linux-musl/release/tloc-explain"
  else
    (cd "${REPO_DIR}" && cargo build --release --offline)
    BIN_SRC="${REPO_DIR}/target/release/tloc-explain"
  fi
fi

install -m 0755 "${BIN_SRC}" "${DEST_DIR}/tloc-explain"
echo "[+] Installed ${DEST_DIR}/tloc-explain ($(ls -lh "${DEST_DIR}/tloc-explain" | awk '{print $5}'))"

case ":${PATH}:" in
  *":${DEST_DIR}:"*) ;;
  *)
    echo "[!] Note: ${DEST_DIR} is not currently in your PATH. Add it or invoke ${DEST_DIR}/tloc-explain directly."
    ;;
esac
