# Arti-rest

If you ever wanted to use tor in a mobile app, up to now you always had to
install a tor-proxy alongside your mobile app. 
Then you could use this tor-proxy to pass all your requests through.
`Arti-rest` is a library that can be directly integrated into an Android
or iOS app if all you want to do is a simple REST request over the Tor network.

Arti-wrapper to use REST over Tor:

```
arti-ios   arti-android
      I     I
     arti-rest
         I
       arti
```
       
`Arti-rest` provides a synchronous interface to send REST requests over tor,
and to receive the answers.
It also does the TLS handling of the connection.
The asynchronous part needs to be done by the Android and iOS library.

## Reliability

Even though we tried our best to produce good code, this should not be used in a
mission critical piece of software without proper consideration of the following:

- arti itself mentions it's not ready for prime-time. In their 
  [README](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md), they write 
  **you should probably not use Arti in production**
- the current code implements caching of the tor-directory listing to avoid having
  to download some megabytes of node descriptors every so often. Again, given the right
  circumstances, this can be effective and secure enough. Under other circumstances
  this is something you don't want to do.
  
## Mobile Libraries

Because iOS XCFrameworks and libraries need to reside in a separate github repository,
we decided to have both Android and iOS in a separate repository:

- [Android](https://github.com/c4dt/arti-android)
- [iOS](https://github.com/c4dt/arti-ios)

You can have a look at these repositories for further instructions how to use the
library.

## Roadmap:

- v0.1 - Simple GET request and reply using TLS - done
- v0.2 - Optimized setting up of the Tor circuit - first version done
- v0.3 - Implement other requests as needed
- v1.0 - Configure arti-rest to either use standard tor, or a pre-configured circuit

## Directories

- `./` is the rust library for the wrapper with arti
- `./ios` holds scripts to create the `XCFramework` used in the `arti-ios`
- `./tools` holds scripts to generate the files for the offline setup of the tor circuits

# Pre-caching of tor circuits

This library has a modified directory controller of arti that allows to use pre-downloaded
circuits.
The idea is to download these circuits once per week, or once per month, and then being
able to setup new circuits with these pre-downloaded circuits.
Of course this requires trusting the server who downloads the circuits.

For more information, see [Directory CAche Setup](tools/README.md)

# License

This is licensed under MPL 2.0
