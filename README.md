# Zenotta Network Protocol

A repo for the development of the Zenotta Network Protocol (ZNP).

[[_TOC_]]

..

## Setup

The Zenotta Network Protocol (in fact, almost all of Zenotta's code) runs on Rust, so installing this is the first step before dealing with any code. You can install `rustup`, Rust's toolchain installer, by running the following:

```
curl https://sh.rustup.rs -sSf | sh
```

When asked how to proceed, simply selecting the option `1) Proceed with installation` is generally the best. You can then run the following to update the `PATH` variable and check whether everything installed correctly:

```
source $HOME/.cargo/env
rustc --version
```

If the terminal responds with the `rustc` version you're currently running then everything went well and you're ready to go. 

### Linux

Linux (Ubuntu 20.04.01 LTS) may require extra package installations depending on what you've developed before. The following package installs assume a completely new machine instance, and should cover everything you need to get going:

```
sudo apt install build-essential
sudo apt-get install m4
sudo apt-get install llvm
sudo apt-get install libclang-dev
```

### Repo Setup

You can then set up the project on your local machine using the following steps:

- Clone this repo using one of the options in Gitlab
- From your terminal, move into the cloned folder on your local machine
- Run the following:

```
make
```

You will also require a local instance of the Zenotta `NAOM` repo, which is a crate dependency. The dependency 
is listed in the `Cargo.toml` as:

```
naom = { path = "../naom" }
```

The path can be changed as needed. Once done you can build the project using `cargo build` and run it using `cargo run`, as per usual.

..

## Running Nodes Locally

You can build everything by running

```rust
cargo build --release
```

This will compile everything into a release state, from which you can then run your nodes locally. The following are example commands for each type to get you up and running quickly:

- **Compute**: `RUST_LOG="$COMPUTE_LOG" target/release/compute --config=src/bin/node_settings_local_raft_1.toml`
- **Storage**: `RUST_LOG=warp target/release/storage --config=src/bin/node_settings_local_raft_1.toml`
- **Miner**: `RUST_LOG="$MINER_LOG" target/release/user --config=src/bin/node_settings_local_raft_1.toml`
- **User**: `RUST_LOG=warp target/release/user --config=src/bin/node_settings_local_raft_1.toml`

You can provide a number of flags to the command depending on the type of node, and you can view information on the available flags for each node type by running the compiled binary with the `--help` flag (eg. `target/release/storage --help`). You can also run a full, 1 node system in your local environment by running `sh src/bin/node_settings_local_raft_1_run.sh` and perusing the generated logs.

..


## Git Flow

**When working on this repo, please ensure that any branches you may create pull from `develop` regularly. In doing this you 
ensure that your local version has the latest code for the project and minimizes the possibility of unnecessary merge 
conflicts.**

Zenotta's Git flow generally involves working on each new task in a new branch, which you should checkout from `develop` and can be done as in the following example

```
git checkout -b branch_name
```

where `branch_name` would be replaced with your chosen branch name. There is no general branch naming convention aside from two cases:

- *New features*: These should be prefixed with `feature_` and then the branch name (eg. `feature_new_cool_feature`)
- *Bugfixes*: These should be prefixed with `bugfix_` and then the branch name (eg. `bugfix_new_damn_bug`)

Beyond this, it is only expected that branches have sensible naming that describes what the branch involves or is for.

..

## Documentation

Documentation can be built locally with rustdoc by running the following command:

```
cargo +nightly doc --document-private-items
```

The resulting documentation can be found in `target/doc/system/index.html`.

Nightly is required because one of dependencies (`gmp-mpfr-sys`) uses unstable features.
