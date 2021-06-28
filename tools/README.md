# Tools for arti-cache

This directory allows to set up a cached version of the most reliable
tor-nodes for faster circuit setup.

To create the relevant files, you need to do the following:

1. Copy the `authority_``{certificate,identity_key,signing_key}` in the `tools/`-directory
2. run `make`
3. Provide the `directory` directory through the mobile app to the `DirectoryCache.tmp_dir` argument 