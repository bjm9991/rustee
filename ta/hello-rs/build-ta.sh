#!/usr/bin/env bash
# Build a loadable aarch64 hello-rs TA ELF (raw ELF, no RTSG envelope).
#
#   ./ta/hello-rs/build-ta.sh           # release -> target/hello-rs.ta
#   ./ta/hello-rs/build-ta.sh debug
#
# Client smoke:
#   RUSTEE_HELLO_TA=$PWD/target/hello-rs.ta cargo run -p rustee-smoke --bin hello-ca
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

PROFILE="${1:-release}"
TARGET="aarch64-unknown-none"

if ! rustup target list --installed | grep -qx "$TARGET"; then
  rustup target add "$TARGET"
fi

CARGO_ARGS=(build -p hello-rs --target "$TARGET")
if [[ "$PROFILE" == "release" ]]; then
  CARGO_ARGS+=(--release)
  OUTDIR="$ROOT/target/$TARGET/release"
elif [[ "$PROFILE" == "debug" ]]; then
  OUTDIR="$ROOT/target/$TARGET/debug"
else
  echo "usage: $0 [release|debug]" >&2
  exit 2
fi

# Match guest: panic=abort. Linker script is also emitted by ta/hello-rs/build.rs.
export RUSTFLAGS="${RUSTFLAGS:-} -C panic=abort"
cargo "${CARGO_ARGS[@]}"

A="$OUTDIR/libhello_rs.a"
if [[ ! -f "$A" ]]; then
  echo "missing staticlib $A" >&2
  exit 1
fi

HOST="$(rustc -vV | awk '/^host:/{print $2}')"
LLD="$(rustc --print sysroot)/lib/rustlib/${HOST}/bin/rust-lld"
if [[ ! -x "$LLD" ]]; then
  echo "missing rust-lld at $LLD" >&2
  exit 1
fi

LINK="$ROOT/ta/hello-rs/link.ld"
ELF="$OUTDIR/hello-rs.elf"
TA="$ROOT/target/hello-rs.ta"

# rustc does not link crate-type=staticlib. lld + KEEP(.rustee.ta_head) produces the ELF
# load_image accepts (section headers + TA_* in .symtab). Do not wrap RTSG.
"$LLD" -flavor gnu \
  --gc-sections \
  --strip-debug \
  -z max-page-size=4096 \
  -T "$LINK" \
  -o "$ELF" \
  --start-group "$A" --end-group

# Host binutils objcopy often cannot retarget aarch64; KEEP in link.ld is the real keep.
if command -v llvm-objcopy >/dev/null 2>&1; then
  llvm-objcopy --set-section-flags .rustee.ta_head=alloc,contents,readonly "$ELF" "$ELF" || true
fi

cp -f "$ELF" "$TA"
echo "wrote $TA"

if command -v readelf >/dev/null 2>&1; then
  readelf -S "$TA" | grep -E 'rustee.ta_head|\.text' || true
  readelf -s "$TA" | grep TA_ || true
fi
