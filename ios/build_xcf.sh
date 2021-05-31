#!/bin/bash

MODE=release
XCFRAMEWORK_ARGS=""
# aarch64-apple-ios
for arch in x86_64-apple-ios ; do
	cargo build --target $arch --$MODE
	tdir=../target/$arch/$MODE
  mkdir -p $tdir/headers
	cp arti-rest.h module.modulemap $tdir/headers
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -library $tdir/libcore.a"
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -headers $tdir/headers/"
done

XCFFILE=arti-rest.xcframework
rm -rf $XCFFILE
xcodebuild -create-xcframework $XCFRAMEWORK_ARGS -output $XCFFILE
