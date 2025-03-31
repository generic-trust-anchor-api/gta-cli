# Generic Trust Anchor API - Command Line Interface

## Introduction
The repository provides a command line interface for the [Generic Trust Anchor API](https://github.com/generic-trust-anchor-api/). It
exposes GTA API library functions to the command line and provides high-level use-case examples.

## Dependencies
The CLI depends on [GTA API Core](https://github.com/generic-trust-anchor-api/gta-api-core) and [GTA API SW Provider](https://github.com/generic-trust-anchor-api/gta-api-sw-provider).

## Local build
- In the project root, initialize build system and build directory (like ./configure for automake):
```
$ meson setup <build_dir>
```
- Compile the code, the build directory is specified with the `-C` option:
```
$ ninja -C <build_dir>
```
* To install the following target can be used:
```
$ sudo ninja -C <build_dir> install
```

## Using the CLI
The CLI reads the environment variable `GTA_STATE_DIRECTORY` and provides it to GTA API SW Provider to persist its state.
If the environment variable `GTA_STATE_DIRECTORY` isn't set the default directory `./gta_state` is used.

- `gta-cli --help` shows the parameters supported by the cli and how to run it
- `gta-cli <FUNCTION> --help` shows function specific help 

Return code:
- returns EXIT_SUCCESS on success
- returns EXIT_FAILURE in case of error