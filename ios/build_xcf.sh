#!/bin/bash

set -e

# This should theoretically also work with 'debug' and be much faster for
# testing.
# However, the creation of the xcframework fails, according to
# https://github.com/rust-lang/rust/issues/79408...
MODE=release

MODEFLAG=
if [ "$MODE" = "release" ]; then
  MODEFLAG=--release
fi

XCFRAMEWORK_ARGS=""
ARCHS="x86_64-apple-ios aarch64-apple-ios"
if [ "$1" = dev ]; then
  ARCHS=x86_64-apple-ios
fi

for arch in $ARCHS; do
	cargo build --target $arch $MODEFLAG
	tdir=../target/$arch/$MODE
  rm -rf $tdir/headers
  mkdir -p $tdir/headers/arti-rest
	cp arti-rest.h module.modulemap $tdir/headers/arti-rest
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -library $tdir/libcore.a"
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -headers $tdir/headers/arti-rest"
done

XCFFILE=arti-rest.xcframework
rm -rf $XCFFILE
xcodebuild -create-xcframework $XCFRAMEWORK_ARGS -output $XCFFILE
