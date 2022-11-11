0.4.6 - 2022/11/11
	* Updating to arti-client 0.7 from arti 1.0.1
	* Also updating all other tor-* crates

0.4.5 - 2022/11/09
	* Support ARM Macs

0.4.4 - 2022/08/26
	* Moving back version-# in Cargo.toml to 0.4.4

0.4.3 - 2022/08/04
	* Updating to arti 0.6
	* Fixing iOS compilation errors

0.4.2 - 2022/04/14
	* Update roadmap in README

0.4.1 - 2022/04/12
	* Fix a couple of issues preventing loading some sites (#92)
	* Move to upstream arti 0.2

0.4.0 - 2022/03/31
	* Expose a full Client
	* Android: split TorLibApi_torRequest in Client_{create,send,free}
	* iOS: split call_arti in client_{new,send,free}
	* Rename library to lightarti-rest
	* Use rustls, see tokio-rs/tls#96

0.3.3 - 2021/08/06
	* More renaming

0.3.2 - 2021/08/06
	* Rename to lightarti-rest

0.3.1 - 2021/08/03
	* Debugging iOS XCFramework

0.3.0 - 2021/08/02
	* Updated using new cache-directory including certificate

0.2.1 - 2021/07/06
	* Fix mac test

0.2.0 - 2021/07/06
	* First working mobile library using the cached tor-directory
