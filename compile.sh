#!/bin/bash
set -e

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
echo "=== iOS SDK Path: $SDK ==="

OBJS=()

compile_file() {
    local src="$1"
    local obj="${src//\//_}.o"
    echo "Compiling $src..."
    clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 -fobjc-arc -Wno-everything \
      -DFF_3105_MCM=1 \
      -I. -I./vendor/worse_query \
      -c "$src" -o "$obj"
    OBJS+=("$obj")
}

# Compile main C/ObjC files
for f in *.m *.c; do
    [ -f "$f" ] && compile_file "$f"
done

# Compile vendor files (worse_query)
if [ -d "vendor" ]; then
    while IFS= read -r f; do
        [ -f "$f" ] && compile_file "$f"
    done < <(find vendor -type f \( -name "*.c" -o -name "*.m" \))
fi

echo "=== Linking Binary ==="
clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 \
  -Wl,-w \
  -framework UIKit -framework Foundation -framework CoreFoundation \
  -framework Security -framework QuartzCore -framework AVFoundation \
  -framework AudioToolbox -framework ImageIO -framework CoreGraphics \
  -lz -lcompression \
  -o ZEXInjector \
  "${OBJS[@]}"

echo "=== Packaging IPA ==="
mkdir -p Payload/ZEXInjector.app
cp ZEXInjector Payload/ZEXInjector.app/
cp Info.plist Payload/ZEXInjector.app/ 2>/dev/null || true
if [ -d Resources ]; then
    cp -R Resources/. Payload/ZEXInjector.app/ 2>/dev/null || true
fi

if command -v ldid &> /dev/null; then
    if [ -f entitlements.plist ]; then
        ldid -Sentitlements.plist Payload/ZEXInjector.app/ZEXInjector || true
    else
        ldid -S Payload/ZEXInjector.app/ZEXInjector || true
    fi
fi

zip -qry ZEX_EXTERNAL.ipa Payload
ls -lh ZEX_EXTERNAL.ipa
echo "=== IPA BUILD COMPLETE ==="
