#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

# This script illustrates the build steps for `vmlinux-hello-busybox`.

set -e

WORKDIR="/tmp/vmlinux_busybox"
SOURCE=$(readlink -f "$0")
TEST_RESOURCE_DIR="$(dirname "$SOURCE")"

KERNEL="linux-4.14.176"
KERNEL_ARCHIVE="$KERNEL.tar.xz"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v4.x/$KERNEL_ARCHIVE"

BUSYBOX="busybox-1.26.0"
BUSYBOX_ARCHIVE="$BUSYBOX.tar.bz2"
BUSYBOX_URL="https://busybox.net/downloads/$BUSYBOX_ARCHIVE"

# Reset index for cmdline arguments for the following `getopts`.
OPTIND=1
# Flag for optionally building a guest that halts.
HALT=
# Number of CPUs to use during the kernel build process.
MAKEPROCS=1
# Flag for optionally cleaning the workdir and recompiling the kernel.
CLEAN=

# Supported arguments:
# * `-h`: build a guest that halts.
# * `-j`: compile with `make -j` (on all available CPUs).
#         TODO: pass the value for `-j`.
while getopts "chj:" opt; do
    case "$opt" in
    c)  CLEAN=1
        ;;
    h)  HALT=1
        ;;
    j)  MAKEPROCS=$OPTARG
        ;;
    *)  ;; # Ignore other flags for now.
    esac
done
shift $((OPTIND-1))

cleanup() {
    if [ -n "$CLEAN" ]; then
        echo "Cleaning $WORKDIR..."
        rm -rf "$WORKDIR"
    fi
}

extract_kernel_srcs() {
    echo "Starting kernel build."
    # Download kernel sources.
    echo "Downloading kernel..."
    curl "$KERNEL_URL" > "$KERNEL_ARCHIVE"
    echo "Extracting kernel sources..."
    tar xf "$KERNEL_ARCHIVE"
}

make_kernel_config() {
    # Copy base kernel config.
    # Add any custom config options, if necessary (currently N/A).
    kernel_dir="$1"
    echo "Copying kernel config..."
    cp "$TEST_RESOURCE_DIR/microvm-kernel-initramfs-hello-x86_64.config" "$kernel_dir/.config"
}

make_busybox() {
    kernel_dir="$1"
    nprocs="$2"
    # Move to the directory with the kernel sources.
    pushd "$kernel_dir" &>/dev/null
    # Prepare busybox.
    echo "Downloading busybox..."
    mkdir -p busybox_rootfs
    curl "$BUSYBOX_URL" > "$BUSYBOX_ARCHIVE"
    echo "Extracting busybox..."
    tar xf "$BUSYBOX_ARCHIVE"
    pushd "$BUSYBOX" &>/dev/null
    # Build statically linked busybox.
    cp "$TEST_RESOURCE_DIR/busybox_static_config" .config
    echo "Building busybox..."
    make -j "$nprocs"
    # Package all artefacts somewhere else.
    echo "Packaging busybox..."
    make CONFIG_PREFIX=../busybox_rootfs install
    # Back to kernel dir.
    popd &>/dev/null
    # Back to wherever we were before.
    popd &>/dev/null
}

make_init() {
    halt="$1"
    # Make an init script.
    cd ..
    echo "Creating init script..."
    cat >init <<EOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/bin/echo "                                                   "
/bin/echo "                 _                                 "
/bin/echo "  _ __ _   _ ___| |_    __   ___ __ ___  _ __ ___  "
/bin/echo " | '__| | | / __| __|___\ \ / / '_ \ _ \| '_ \ _ \ "
/bin/echo " | |  | |_| \__ \ ||_____\ V /| | | | | | | | | | |"
/bin/echo " |_|   \__,_|___/\__|     \_/ |_| |_| |_|_| |_| |_|"
/bin/echo "                                                   "
/bin/echo "                                                   "
/bin/echo "Hello, world, from the rust-vmm reference VMM!"
EOF

    if [ -z "$halt" ]; then
        echo "setsid /bin/sh -c 'exec /bin/sh </dev/ttyS0 >/dev/ttyS0 2>&1'" >>init
    else
        echo "exec /sbin/halt" >>init
    fi
}

make_initramfs() {
    kernel_dir="$1"
    halt="$2"

    # Move to the directory with the kernel sources.
    pushd "$kernel_dir" &>/dev/null

    # Prepare initramfs directory.
    mkdir -p initramfs/{bin,dev,etc,home,mnt,proc,sys,usr}
    # Copy busybox.
    echo "Copying busybox to the initramfs directory..."
    cp -r busybox_rootfs/* initramfs/

    # Make a block device and a console.
    pushd initramfs/dev &>/dev/null
    echo "Creating device nodes..."
    rm -f sda && mknod sda b 8 0
    rm -f console && mknod console c 5 1
    rm -f ttyS0 && mknod ttyS0 c 4 64

    make_init "$halt"

    chmod +x init
    fakeroot chown root init

    # Pack it up...
    echo "Packing initramfs.cpio..."
    find . | cpio -H newc -o > ../initramfs.cpio
    fakeroot chown root ../initramfs.cpio

    # Return to kernel srcdir.
    popd &>/dev/null
    # Return to previous directory.
    popd &>/dev/null
}

make_kernel() {
    kernel_dir="$1"
    nprocs="$2"
    dst="$3"

    # Move to the directory with the kernel sources.
    pushd "$kernel_dir" &>/dev/null

    # Build kernel.
    echo "Building kernel..."
    make -j "$nprocs" vmlinux
    # Copy to destination.
    cp vmlinux "$dst"

    # Return to previous directory.
    popd &>/dev/null
}

# Step 0: clean up the workdir, if the user wants to.
cleanup

# Step 1: what are we building?
if [ -n "$HALT" ]; then
    VMLINUX="vmlinux-hello-busybox-halt"
else
    VMLINUX="vmlinux-hello-busybox"
fi

# Step 2: start from scratch.
mkdir -p "$WORKDIR" && cd "$WORKDIR"

# Step 3: acquire kernel sources & config.
extract_kernel_srcs
make_kernel_config "$KERNEL"

# Step 4: make the initramfs.
make_busybox "$KERNEL" "$MAKEPROCS"
make_initramfs "$KERNEL" "$HALT"

# Step 5: put them together.
make_kernel "$KERNEL" "$MAKEPROCS" "$VMLINUX"
cp "$WORKDIR/$KERNEL/$VMLINUX" "$TEST_RESOURCE_DIR"

# Final step: profit!
echo "Done!"
cleanup
exit 0
