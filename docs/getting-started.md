# Getting Started with the Reference VMM

## Contents

- [Getting Started with the Reference VMM](#getting-started-with-the-reference-vmm)
  - [Contents](#contents)
  - [Prerequisites](#prerequisites)
    - [OS & Hypervisor](#os--hypervisor)
  - [Build the Reference VMM](#build-the-reference-vmm)
  - [Run the Reference VMM](#run-the-reference-vmm)
    - [Kernel](#kernel)
    - [Devices](#devices)
    - [Putting It All Together](#putting-it-all-together)

## Prerequisites

### OS & Hypervisor

Currently, the reference VMM runs on Linux **x86_64** hosts, using the **KVM**
hypervisor. To make sure KVM is accessible to your user, run:

```bash
[ -r /dev/kvm ] && [ -w /dev/kvm ] && echo "OK" || echo "FAIL"
```

To grant your user access to KVM, either:

1. If you have the ACL package for your distro installed:

    ```bash
    sudo setfacl -m u:${USER}:rw /dev/kvm
    ```

    or

2. If your distribution uses the `kvm` group to manage access to `/dev/kvm`:

    ```bash
    [ $(stat -c "%G" /dev/kvm) = kvm ] && sudo usermod -aG kvm ${USER}
    ```

    Then log out and back in.

## Build the Reference VMM

To build the reference VMM from source, you need to have the Rust compiler and
`cargo` installed on your system. The following toolchains are supported:

- `x86_64-unknown-linux-gnu` (Linux with `glibc`, **default**)
- `x86_64-unknown-linux-musl` (Linux with `musl libc`)

As the reference VMM does not yet have any compile-time features, building it
is as simple as:

```bash
cargo build [--release]
```

This will produce a binary called `vmm-reference` in the `cargo` build
directory (default: `target/${toolchain}/${mode}`, where mode can be `debug` or
`release`).

## Run the Reference VMM

### Kernel

To build a kernel for the reference VMM to boot, check out the scripts in
[resources/kernel](../resources/kernel).

- [`make_busybox.sh`](../resources/kernel/make_busybox.sh) builds an ELF image
  with a baked-in initramfs running [Busybox](https://busybox.net/). It uses a
  stripped-down
  [kernel config](../resources/kernel/microvm-kernel-initramfs-hello-x86_64.config)
  and a statically linked [config](../resources/kernel/busybox_static_config)
  for the Busybox initramfs.

  ```bash
  ./make_busybox.sh
  ```

  This produces a binary image called `vmlinux-hello-busybox` in the
  `resources/kernel` directory.

### Devices

The reference VMM only supports a serial console device for now. This section
will be expanded as other devices are added.

### Putting It All Together

Once all the prerequisites are met, the reference VMM can be run either
directly through `cargo`, passing on its specific
[command line arguments](../README.md#cli-reference), or after building it with
`cargo build`.

```wrap
cargo run --release --            \
    --memory mem_size_mib=1024    \
    --kernel path=${PWD}/resources/kernel/vmlinux-hello-busybox  \
    --vcpu num=1
```

```wrap
cargo build --release
target/release/vmm-reference      \
    --memory mem_size_mib=1024    \
    --kernel path=${PWD}/resources/kernel/vmlinux-hello-busybox \
    --vcpu num=1
```
