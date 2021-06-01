arxc := arti-rest.xcframework
arxcz := $(arxc).zip

.PHONY: build-ios
build-ios: ios/arti-rest.xcframework $(arxcz)

ios/$(arxc): $(wildcard src/*)
	( cd ios; ./build_xcf.sh )

$(arxcz): ios/$(arxc)
	cd ios && \
	( cd $(arxc) && zip -r ../../$(arxcz) . ) && \
	swift package compute-checksum ../$(arxcz)
