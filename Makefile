arxc := arti-rest.xcframework
arxcz := $(arxc).zip

.PHONY: build-ios
build-ios: $(arxcz)

ios/$(arxc): $(wildcard src/*) ios/arti-rest.h ios/build_xcf.sh
	( cd ios; ./build_xcf.sh )

$(arxcz): ios/$(arxc)
	cd ios && \
	zip -r ../$(arxcz) $(arxc) && \
	swift package compute-checksum ../$(arxcz)

dev:
	perl -pi -e 's/lto = "fat"/lto = "thin"/' Cargo.toml
	perl -pi -e 's/opt-level = "s"/#opt-level = "s"/' Cargo.toml
	cd ios && \
	./build_xcf.sh dev && \
	cp -av arti-rest.xcframework ../../arti-ios
	perl -pi -e 's/lto = "thin"/lto = "fat"/' Cargo.toml
	perl -pi -e 's/#opt-level = "s"/opt-level = "s"/' Cargo.toml
