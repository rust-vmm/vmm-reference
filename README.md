# `vmm-reference`

## Design

The purpose of the reference VMM is twofold:

1. To serve as a starting point in the creation of tailor-made VMMs that users
   build according to their needs. Users can fork the reference VMM, mix and
   match its components and UI to create a functional VMM with a minimal attack
   surface and resource footprint, custom-made to suit their isolation
   requirements.
1. To validate the `rust-vmm` crates that compose it and demonstrate their
   functionality in a use-case-agnostic, end-to-end VMM.

The reference VMM consists of `rust-vmm crates` and minimal glue code that
sticks them together. The crate exposes several `pub fn`s that serve as entry
points for pluggable UIs. A basic command line parser demonstrates how a
frontend can be stitched to the VMM. Any external component that binds to the
reference VMM's public Rust API can replace it.

The reference VMM is also a vehicle for end-to-end testing of `rust-vmm`
crates. Each crate must contain individual functional and performance tests
that exercise as wide a range of use cases as possible; the reference VMM is
not meant to reiterate on that, but to validate all the pieces put together.
The public Rust API facilitates Rust integration tests that exercise it.

## Usage

The reference VMM can be used out of the box as a `hello-world` example of a
fully functional VMM built with `rust-vmm` crates.

```bash
cargo run                       \
    --guest-memory=1024         \
    --vcpus=1                   \
    --kernel=/path/to/vmlinux   \
    --cmdline="cmdline"
    [--blk=<blkdev_config> - TBD]
    [--net=<netdev_config> - TBD]
```

The crate's [`Cargo.toml`](Cargo.toml) controls which VMM functionalities are
available. By default, all rust-vmm crates are listed as dependencies and
therefore included. Users can play freely with the building blocks by modifying
the TOML, and the prepackaged CLI can quickly validate the altered
configurations. Advanced users can, of course, plug in their own front-end.

## CLI reference

**TODO**

## License

This project is licensed under either of:

- [Apache License](LICENSE-APACHE), Version 2.0
- [BSD-3-Clause License](LICENSE-BSD-3-CLAUSE)
