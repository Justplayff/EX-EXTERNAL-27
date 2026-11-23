#!/bin/bash
set -e

SDK=$(xcrun --sdk iphoneos --show-sdk-path)
echo "=== iOS SDK Path: $SDK ==="

OBJS=()

compile_file() {
    local src="$1"
    local obj="${src//\//_}.o"
    echo "Compiling $src..."
    clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 -O2 -fvisibility=hidden -fobjc-arc -Wno-everything \
      -DFF_3105_MCM=1 \
      -I. -Ivendor -I./vendor/worse_query \
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
  -o JUSTPLAYFFInjector \
  "${OBJS[@]}"

echo "=== Packaging IPA ==="
mkdir -p Payload/JUSTPLAYFFInjector.app
cp JUSTPLAYFFInjector Payload/JUSTPLAYFFInjector.app/
strip -x Payload/JUSTPLAYFFInjector.app/JUSTPLAYFFInjector 2>/dev/null || true
cp Info.plist Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
if [ -d Resources ]; then
    cp -R Resources/. Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
fi
# Copy icon files if they exist
cp app_logo.png Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
cp AppIcon60x60@2x.png Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
cp AppIcon60x60@3x.png Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
cp AppIcon76x76@2x.png Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true
cp AppIcon83.5x83.5@2x.png Payload/JUSTPLAYFFInjector.app/ 2>/dev/null || true

if command -v ldid &> /dev/null; then
    if [ -f entitlements.plist ]; then
        ldid -Sentitlements.plist Payload/JUSTPLAYFFInjector.app/JUSTPLAYFFInjector || true
    else
        ldid -S Payload/JUSTPLAYFFInjector.app/JUSTPLAYFFInjector || true
    fi
fi

zip -qry JUST_PLAY_FF_EXTERNAL.ipa Payload
ls -lh JUST_PLAY_FF_EXTERNAL.ipa
echo "=== IPA BUILD COMPLETE ==="
