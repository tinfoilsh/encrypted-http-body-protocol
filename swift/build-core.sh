#!/bin/sh
# Builds swift/EHBPCore.xcframework from the Rust C ABI crate (rust/ffi) for
# every Apple target rustup has installed: macOS always (arm64, x86_64 lipo'd
# when both are present), iOS device and simulator only if their targets are
# installed. The xcframework is assembled by hand (no Xcode needed) and is
# not committed; conformance/spec/swift-ffi.md describes the release step.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CRATE="$ROOT/rust/ffi"
OUT="$ROOT/swift/EHBPCore.xcframework"
INSTALLED=$(rustup target list --installed)
HOST=$(rustc -vV | sed -n 's/^host: //p')

has() { echo "$INSTALLED" | grep -qx "$1" || [ "$1" = "$HOST" ]; }

build() { # target
  cargo build --release --manifest-path "$CRATE/Cargo.toml" --target "$1" --quiet
  echo "$CRATE/target/$1/release/libehbp_ffi.a"
}

# slice <platform> <variant-or-empty> <arch=target...>: builds the slice for
# every arch whose target is installed; skipped when none is.
PLIST=""
slice() {
  platform=$1 variant=$2; shift 2
  libs=""; archs=""
  for pair in "$@"; do
    arch=${pair%%=*}; target=${pair#*=}
    has "$target" || continue
    libs="$libs $(build "$target")"; archs="$archs $arch"
  done
  [ -n "$libs" ] || return 0
  name="$platform-$(echo $archs | tr ' ' '_')${variant:+-$variant}"
  dir="$OUT/$name"; mkdir -p "$dir/Headers"
  lipo -create $libs -output "$dir/libehbp_ffi.a"
  cp "$CRATE/include/ehbp.h" "$dir/Headers/"
  printf 'module EHBPCore {\n    header "ehbp.h"\n    export *\n}\n' > "$dir/Headers/module.modulemap"
  archlist=""; for a in $archs; do archlist="$archlist<string>$a</string>"; done
  PLIST="$PLIST<dict><key>HeadersPath</key><string>Headers</string><key>LibraryIdentifier</key><string>$name</string><key>LibraryPath</key><string>libehbp_ffi.a</string><key>SupportedArchitectures</key><array>$archlist</array><key>SupportedPlatform</key><string>$platform</string>${variant:+<key>SupportedPlatformVariant</key><string>$variant</string>}</dict>"
  echo "built $name ($archs )"
}

rm -rf "$OUT"
slice macos "" arm64=aarch64-apple-darwin x86_64=x86_64-apple-darwin
slice ios "" arm64=aarch64-apple-ios
slice ios simulator arm64=aarch64-apple-ios-sim x86_64=x86_64-apple-ios
cat > "$OUT/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>AvailableLibraries</key><array>$PLIST</array><key>CFBundlePackageType</key><string>XFWK</string><key>XCFrameworkFormatVersion</key><string>1.0</string></dict></plist>
PLIST
