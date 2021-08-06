# Tools for arti-cache

## Overview

To send some data anonymously over the network, Lightarti-rest relies on a
subset of relays of the Tor network.

This script allows to set up a snapshot of the most reliable Tor relays
for faster circuit setup.

You will have to create a custom directory authority, and to periodically
run this script on a trusted server.

Then the app will have to download the files, put them in a directory,
and send the path to this directory to the library.

## Requirements

This script requires Python 3 (version >= 3.7), as well as
the libraries Stem (version >= 1.8.0), PyCryptodome
(version >= 3.10.1), and Cryptography.

It is advised to install the required libraries with `pip`:

```
pip install -r requirements.txt
```

Also, to create the directory authority's certificate, this script
relies on the program `tor-gencert` that you will have to install on
your machine. For a debian based distribution, this program is usually
installed by the package `tor`:

```
sudo apt-get install tor
```

## Generating Directory Info

We provide a Makefile allowing you to generate all the files you need
for running Lightarti-rest. First you will need to set a password to encrypt
some private data of the custom authority via an environment variable,
then create the authority and its certificate:

```
export DIR_AUTH_PASSWORD='dummypassword'
make certificate
```

Then you will have to create the fresh directory info.

```
make dirinfo
```

We configured it to place the files required by Lightarti-rest in the
sub-directory `directory-cache`, and the private data of the custom
directory authority in the sub-directory `authority-private`.

Once the data is generated, you can use the subdirectory `directory-cache`
as the `cache_dir` argument.

### Custom Directory Authority

As the directory information needs to be signed, you will need to
create a custom directory authority with a valid certificate. The
script can generate it by using its `generate-certificate`
sub-command.

This step is required, but you only need to do it to create the
custom directory authority and when renewing its certificate.

As `tor-gencert` requires the identity key of the directory
authority to be encrypted, you need to pass a password to the script
via an environment variable.

```
export DIR_AUTH_PASSWORD='dummypassword'
```

Then you can call the script.

```
python3 gen_fresh_dirinfo.py generate-certificate \
  --authority-identity-key authority_identity_key \
  --authority-signing-key authority_signing_key \
  --authority-certificate certificate.txt \
  --authority-v3ident authority.txt \
  --authority-name spring \
  --certificate-validity-months 12
```

Which creates 4 files:

- The identity key of the authority which you should keep private in a
  secure location. (default: `authority_identity_key`)
- The signing key of the authority which you should keep private and
  that you will need for generating the directory information.
  (default: `authority_signing_key`)
- The certificate of the authority which you will need for generating
  the directory information and which you will need to provide to the
  Lightarti-rest library. (default: `certificate.txt`)
- A small file containing the v3ident identifier of the authority which
  you will need to provide to the Lightarti-rest library. (default:
  `authority.txt`)

**Note:** If the files already exist when running the script, it will
renew the certificate instead of regenerating a new identity key.


### Generate Directory Information

To generate the directory information, you will need to run the
`generate-dirinfo` sub-command of this script regularly on a trusted
server.

```
python3 gen_fresh_dirinfo.py generate-dirinfo \
  --authority-signing-key authority_signing_key \
  --authority-name spring \
  --authority-contact 'SPRING Lab at EPFL' \
  --authority-certificate certificate.txt \
  --consensus consensus.txt \
  --consensus-validity-days 7 \
  --microdescriptors microdescriptors.txt \
  --number-routers 120
```

This sub-command effectively creates a snapshot of the most
reliable advertised relays in the Tor network in the form of two files:

- A customized consensus containing metadata related to a subset of
  routers present in the Tor network. (default: `consensus.txt`)
- A file containing a list of microdescriptors, each router described
  in the consensus is described by one microdescriptor. (default:
  `microdescriptors.txt`)


## Generate Churn (Incomplete)

To improve the reliability of the subset of the Tor network upon which
Lightarti-rest relies to build a circuit, we are providing a way to compute
a list of no-longer working relays.

This is a work in progress, currently Lightarti-rest is not able to handle
this list.
