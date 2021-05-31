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

# License

This is licensed under MPL 2.0
