# Tools for arti-cache

This directory allows to set up a cached version of the most reliable
tor-nodes for faster circuit setup.
You will have to let this run on a regular basis on a trusted server.
Then the app will have to download the files, put them in a directory,
and send the path to this directory to the library.

Currently, you have to do the following:

To create the relevant files, you need to do the following:

1. Copy the `authority_``{certificate,identity_key,signing_key}` in the `tools/`-directory
2. run `make` in the `tools`-directory
3. include the `directory-cache` directory into the assets of your app
4. Pass the path to the `directory-cache` in the `cache_dir` argument 

## TODO

- [make custom directory authority configurable](https://github.com/c4dt/arti-rest/issues/41)
- [add scripts to repo](https://github.com/c4dt/arti-rest/issues/39)
