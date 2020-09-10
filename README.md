# `vmm-reference`

## Design

The purpose of the reference VMM is twofold:

1. To validate the `rust-vmm` crates that compose it and demonstrate their
   functionality in a use-case-agnostic, end-to-end VMM.
1. To serve as a starting point in the creation of tailor-made VMMs that users
   build according to their needs. Users can fork the reference VMM, mix and
   match its components and UI to create a functional VMM with a minimal attack
   surface and resource footprint, custom-made to suit their isolation
   requirements.

The reference VMM consists of `rust-vmm` crates and minimal glue code that
sticks them together. The end result is a binary, roughly split between a
simple CLI and a `vmm` crate, which ingests all the available `rust-vmm`
building blocks compiled with all their available features. As crate
development progresses, in the future, we may have feature `X` in crate `A`
mutually incompatible with feature `Y` in crate `B` - therefore the reference
VMM, which depends on both crates `A` and `B`, will no longer support features
`X` and `Y` simultaneously. If and when this situation occurs, multiple
binaries for the reference VMM will be supplied.

The `vmm` crate exposes several entry points (`pub fn`s) for pluggable UIs. A
basic command line parser demonstrates how a frontend can be stitched to the
VMM. Any external component that binds to the reference VMM's public Rust API
can replace it.

The reference VMM is, first and foremost, a vehicle for end-to-end testing of
`rust-vmm` crates. Each crate must contain individual functional and
performance tests that exercise as wide a range of use cases as possible; the
reference VMM is not meant to reiterate on that, but to validate all the pieces
put together. The public Rust API facilitates Rust integration tests that
exercise it. The Rust integration tests make use of the VMM in varied
configurations that aren’t overly complex and illustrate realistic use cases
(e.g. one test runs a VMM with virtio MMIO devices, one test runs a VMM with
PCI, etc.). Initially, we will start with a single test that illustrates usage
of the only currently available device (the serial console).

For more details, see [`DESIGN.md`](docs/DESIGN.md).

## Usage

The reference VMM can be used out of the box as a `hello-world` example of a
fully functional VMM built with `rust-vmm` crates.

```bash
vmm-reference                                                           \
    --memory mem_size_mib=1024                                          \
    --vcpus num_vcpus=1                                                 \
    --kernel path=/path/to/vmlinux,himem_start=1024,cmdline="console=ttyS0 pci=off"\
    [--blk <blkdev_config> - TBD]
    [--net <netdev_config> - TBD]
```

The crate's [`Cargo.toml`](Cargo.toml) controls which VMM functionalities are
available. By default, all rust-vmm crates are listed as dependencies and
therefore included. Users can play freely with the building blocks by modifying
the TOML, and the prepackaged CLI can quickly validate the altered
configurations. Advanced users can, of course, plug in their own front-end.

## CLI reference

* `memory` - guest memory configurations
  * `mem_size_mib` - `u32`, guest memory size in MiB (decimal)
* `kernel` - guest kernel configurations
  * `path` - `String`, path to the guest kernel image
  * `cmdline` - `String`, kernel command line
  * `himem_start` - `u64`, start address for high memory (decimal)
* `vcpus` - vCPU configurations
  * `num_vcpus` - `u8`, number of vCPUs (decimal)

## License

This project is licensed under either of:

* [Apache License](LICENSE-APACHE), Version 2.0
* [BSD-3-Clause License](LICENSE-BSD-3-CLAUSE)
