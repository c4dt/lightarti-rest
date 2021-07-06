# arti-rest

Arti-wrapper to use REST over Tor:

arti-ios   arti-android
      I     I
     arti-rest
         I
       arti
       
arti-rest provides a synchronous interface to send REST requests over tor,
and to receive the answers.
It also does the TLS handling of the connection.
The asynchronous part needs to be done by the android and ios library.

## Roadmap:

- v0.1 - Simple GET request and reply using TLS
- v0.2 - Optimized setting up of the Tor circuit
- v0.3 - Implement other requests as needed
- v1.0 - Configure arti-rest to either use standard tor, or a pre-configured circuit

## Directories

- `./` is the rust library for the wrapper with arti
- `./ios` holds scripts to create the `XCFramework` used in the `arti-ios`

# Pre-caching of tor circuits

This library has a [modified directory manager](./src/arti/tor-dirmgr) of arti that allows to 
use pre-downloaded circuits.
The idea is to download these circuits once per week, or once per month, and then being
able to setup new circuits with these pre-downloaded circuits.
Of course this requires trusting the server who provide the circuits.

For more information, see [Directory Cache Setup](tools/README.md)

# License

This is licensed under MPL 2.0
