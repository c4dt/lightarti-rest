arxc := lightarti-rest.xcframework
arxcz := $(arxc).zip

LATEST_DIRCACHE_URL := https://github.com/c4dt/lightarti-directory/releases/latest/download/directory-cache.tgz

SRCS := $(shell find src -name '*.rs')

.PHONY: build-ios
build-ios: $(arxcz)

$(HOME)/.cargo/bin/cbindgen:
	cargo install cbindgen
ios/lightarti-rest.h: $(HOME)/.cargo/bin/cbindgen cbindgen.toml
	$< > $@

ios/$(arxc): $(SRCS) ios/lightarti-rest.h ios/build_xcf.sh
	( cd ios; ./build_xcf.sh )

$(arxcz): ios/$(arxc)
	cd ios && \
	zip -r ../$(arxcz) $(arxc) && \
	swift package compute-checksum ../$(arxcz)

dev:
	perl -pi -e 's/lto = "fat"/lto = "thin"/' Cargo.toml
	perl -pi -e 's/.*opt-level = "s"/#opt-level = "s"/' Cargo.toml
	rm -rf ../lightarti-rest-ios/lightarti-rest.xcframework
	cd ios && \
	./build_xcf.sh dev && \
	cp -av lightarti-rest.xcframework ../../lightarti-rest-ios
	perl -pi -e 's/lto = "thin"/lto = "fat"/' Cargo.toml
	perl -pi -e 's/.*#opt-level = "s"/opt-level = "s"/' Cargo.toml

.PHONY: dircache

dircache:
	mkdir -p directory-cache
	wget --output-document - --quiet '$(LATEST_DIRCACHE_URL)' | tar -C directory-cache -zxf -
