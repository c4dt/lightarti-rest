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

function build {
  cargo build --target $1 $MODEFLAG
}

function create_universal {
  tdir=../target/universal/$MODE

  rm -rf $tdir
  mkdir -p $tdir

  lipo -create \
    -arch x86_64 ../target/$1/$MODE/liblightarti_rest.a \
    -arch arm64 ../target/$2/$MODE/liblightarti_rest.a \
    -output $tdir/liblightarti_rest.a
}

function prepare_target {
  tdir=../target/$1/$MODE
  hdir=$tdir/lightarti-rest

  rm -rf $hdir
  mkdir -p $hdir

  cp lightarti-rest.h module.modulemap $hdir

  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -library $tdir/liblightarti_rest.a"
  XCFRAMEWORK_ARGS="${XCFRAMEWORK_ARGS} -headers $hdir"
}

# Build x86 simulator target (for Intel Macs).
build x86_64-apple-ios

# Build ARM simulator target (for ARM Macs).
build aarch64-apple-ios-sim

# Create universal binary library for simulators.
create_universal x86_64-apple-ios aarch64-apple-ios-sim

# Copy headers and configure xcodebuild.
prepare_target universal

# Build iOS target.
build aarch64-apple-ios

# Copy headers and configure xcodebuild.
prepare_target aarch64-apple-ios

# Build xcframework package.
XCFFILE=lightarti-rest.xcframework
rm -rf $XCFFILE
xcodebuild -create-xcframework $XCFRAMEWORK_ARGS -output $XCFFILE
