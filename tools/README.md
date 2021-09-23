# Tools for generating custom directory information

To reduce bandwidth use of lightarti-rest, the library relies on custom Tor directory information. The scripts in the `tools/` directory generate the required files, that can then be downloaded by apps for use with lightarti-rest.

The scripts in this directory aim to pick reliable nodes so that ideally the consensus can be used for up to a week. We refer to the [accompanying Jupyter notebook](churn_analysis.ipynb) for a historical analysis of churn on the Tor network that shows shows that this approach is viable.

The tool provides three functions:

1. Setting up a custom directory authority. The keys of this authority are used to sign the smaller custom consensus files. This step only needs to be run once.
2. Generating a new custom consensus. Based on the latest consensus information, the script produces a smaller consensus of reliable nodes.  A new custom consensus should ideally be generated at least once a day. Generating a new custom consensus requires the keys from the previous step.
3. Generating a churn file. As a custom consensus ages, some nodes may no longer be available. To increase efficiency, lightarti-rest can take as input a very small churn file that lists available nodes. A churn file is generated with respect to a specific custom consensus. Ideally it is updated every hour.

We describe these in more detail below.

## Requirements

This script requires Python 3 (version >= 3.7), as well as the libraries Stem
(version >= 1.8.0), PyCryptodome (version >= 3.10.1), and Cryptography.

We recommend to install the required libraries with `pip`:

```
pip install -r requirements.txt
```

Also, to create the directory authority's certificate, this script
relies on the program `tor-gencert` that you will have to install on
your machine. For a Debian-based distribution, this program is usually
installed by the package `tor`:

```
sudo apt-get install tor
```

## A quick start

We provide a Makefile allowing you to generate all the files you need
for using Lightarti-rest.

When first using lightarti-rest in a new context, you must create a custom directory authority and the corresponding keys and certificates. The private keys of the custom directory authority will be password protected before writing them to disk. The Makefile assumes that the environment variable `DIR_AUTH_PASSWORD` contains this password.

To set up the custom directory authority, run:

```
export DIR_AUTH_PASSWORD='dummypassword'
make certificate
```

This is a one-time operation. The private data of the custom
directory authority are written to the sub-directory `authority-private`.

To generate an updated custom consensus containing fresh directory information, run:

```
make dirinfo
```

The Makefile writes the resulting files to the `directory-cache/` directory. Lightarti-rest relies on the files in this directory for its operation. Apps should download this directory and supply it as the `cache_dir` argument.

## Using the scripts directly

You can also call the `gen_fresh_dirinfo.py` script directly. This gives you more control than using the Makefile.

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

To generate updated directory information, you must run the
`generate-dirinfo` sub-command of this script. We recommend to do so regularly, but at least once a day.

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
reliable advertised routers in the Tor network in the form of two files:

- A customized consensus containing metadata related to a subset of
  routers present in the Tor network. (default: `consensus.txt`)
- A file containing a list of microdescriptors, each router described
  in the consensus is described by one microdescriptor. (default:
  `microdescriptors.txt`)


## Generate Churn

To improve the reliability of the subset of the Tor network upon which
Lightarti-rest relies to build circuits, we are providing a way to compute
a list of no longer available/reachable routers.

This list of unavailable routers is intended to be a lightweight file containing
up-to-date info about routers that are no longer reachable with the info
contained in the current customized consensus.

Once generated, you can additionally provide the churn file to Lightarti-rest.
Lightarti-rest will then ignore any routers that are marked as unavailable when
building a circuit.

To generate this file containing the no longer working routers in a customized
consensus, you will need to run the `compute-churn` sub-command of this script
at least once a day on a trusted server.

```
./gen_fresh_dirinfo.py compute-churn \
		--churn churn.txt \
		--consensus consensus.txt
```

This subcommand, essentially parses a customized consensus and compare its info
with up-to-date data retrieved from Tor's directory authorities.
