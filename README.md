# Arti-rest


Arti-rest is a simple wrapper around [arti](https://gitlab.torproject.org/tpo/core/arti) that leverages arti to enable mobile apps to easily make anonymous REST requests via the Tor network. Arti-rest makes two changes on top of arti. First, arti-rest provides a simple wrapper for REST requests, to make calling HTTP(S) API endpoints easier. Second, arti-rest provides the option to use a customized, and therefore potentially much smaller, consensus. 

> :warning: **Warning: arti-rest is not secure in all situations** Arti-rest modifies several core parts of `arti`. These modifications result on arti-rest not providing the same guarantees than arti and the stock Tor client. You will have to verify on your own whether these weakened guarantees are acceptable in your situation. See the reliability section below to check what aspects of your system you need to consider to decide whether arti-rest is secure for you.

Arti-rest is written in Rust and can therefore be compiled into native libraries that are easy to integrate into mobile applications. All credits for enabling this approach go to the authors of [arti](https://gitlab.torproject.org/tpo/core/arti). Using a native library ensures that arti-rest can be bundled with Android and iOS applications, rather than relying on external Tor proxies that must be installed separately.

To facilitate integration in mobile applications, we provide the [arti-ios](https://github.com/c4dt/arti-ios) and [arti-android](https://github.com/c4dt/arti-android) libraries. The following graph shows how these libraries interact.

```
arti-ios   arti-android
      I     I
     arti-rest
         I
       arti
```
       
`Arti-rest` provides a synchronous interface to send REST requests over Tor, and
to receive the answers. It also does the TLS handling of the connection. The
asynchronous part needs to be done by the Android and iOS library.

## Reliability

Even though we tried our best to produce good code, this should not be used in a
mission critical piece of software without proper consideration of the following:

- arti itself mentions it's not ready for prime-time since it does not implement all protections that the stock Tor client does. See their [README](https://gitlab.torproject.org/tpo/core/arti/-/blob/main/README.md) to check whether your application can be secure without those protections.
- arti-rest uses a customized consensus to reduce bandwidth cost for infrequent use of arti-rest. As a result, the consensus is not signed by the default Tor directory authorities, but instead by the creator of the app. This approach in general is not secure. However, since the app developer already determines which code is loaded (and could therefore disable consensus validation altogether, or deanonymize users directly), it is likely acceptable in the case of mobile applications that directly include arti-rest. 

In summary, you should only use `arti-rest` when you understand the differences between `arti` and `arti-rest` and Tor, and you are certain that the loss of protection with respect to Tor does not harm the security of your users. 
  
## Mobile Libraries

Because iOS XCFrameworks and libraries need to reside in a separate GitHub repository,
we decided to have both Android and iOS in a separate repository:

- [Android](https://github.com/c4dt/arti-android)
- [iOS](https://github.com/c4dt/arti-ios)

You can have a look at these repositories for further instructions how to use the
library.

### Test apps

The Android test app is in the `arti-android` repository.
For the iOS test app, see here:
[arti-ios-test](https://github.com/c4dt/arti-ios-test)


## Roadmap:

- v0.1 - Simple GET request and reply using TLS - done
- v0.2 - Optimized setting up of the Tor circuit - first version done
- v0.3 - Add certificate configurations to the tor-cache directory   
- v0.4 - Configure arti-rest to either use standard tor, or a pre-configured circuit
- v1.0 - Once arti is deemed stable enough, and other people have looked and used this code

## Directories

- `./` is the rust library for the wrapper with arti
- `./ios` holds scripts to create the `XCFramework` used in the `arti-ios`
- `./tools` holds scripts to generate the files for the offline setup of the tor circuits

# Pre-caching of Tor circuits

This library has a [modified directory manager](./src/arti/tor-dirmgr) of arti that allows to 
use pre-downloaded circuits.
The idea is to download these circuits once per week, or once per month, and then being
able to setup new circuits with these pre-downloaded circuits.
Of course this requires trusting the server who provide the circuits.

For more information, see [Directory Cache Setup](tools/README.md)

# License

This is licensed under MPL 2.0
