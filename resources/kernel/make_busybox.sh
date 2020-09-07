#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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

rm -rf "$WORKDIR" && mkdir "$WORKDIR" && cd "$WORKDIR"

# Download kernel sources.
echo "Downloading kernel..."
curl "$KERNEL_URL" > "$KERNEL_ARCHIVE"
echo "Extracting kernel sources..."
tar xf "$KERNEL_ARCHIVE"
pushd "$KERNEL" &>/dev/null

# Copy base kernel config.
cp "$TEST_RESOURCE_DIR/microvm-kernel-initramfs-hello-x86_64.config" .config

# Prepare busybox.
echo "Downloading busybox..."
mkdir -p busybox_rootfs
curl "$BUSYBOX_URL" > "$BUSYBOX_ARCHIVE"
echo "Extracting busybox..."
tar xf "$BUSYBOX_ARCHIVE"
pushd "$BUSYBOX" &>/dev/null
# Build statically linked busybox.
cp "$TEST_RESOURCE_DIR/busybox_static_config" .config
make -j
# Package all artefacts somewhere else.
make CONFIG_PREFIX=../busybox_rootfs install
# Back to kernel dir.
popd &>/dev/null

# Prepare initramfs directory.
mkdir -p initramfs/{bin,dev,etc,home,mnt,proc,sys,usr}
# Copy busybox.
cp -r busybox_rootfs/* initramfs/

# Make a block device and a console.
pushd initramfs/dev &>/dev/null
mknod sda b 8 0
mknod console c 5 1

# Make an init script.
cd ..
cat >init <<EOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
/bin/echo "                                                   "
/bin/echo "                 _                                 "
/bin/echo "  _ __ _   _ ___| |_    __   ___ __ ___  _ __ ___  "
/bin/echo " | '__| | | / __| __|___\ \ / / '_ ` _ \| '_ ` _ \ "
/bin/echo " | |  | |_| \__ \ ||_____\ V /| | | | | | | | | | |"
/bin/echo " |_|   \__,_|___/\__|     \_/ |_| |_| |_|_| |_| |_|"
/bin/echo "                                                   "
/bin/echo "                                                   "
/bin/echo "Hello, world, from the rust-vmm reference VMM!"
exec /bin/sh
EOF
chmod +x init
fakeroot chown root init

# Pack it up...
find . | cpio -H newc -o > ../initramfs.cpio
fakeroot chown root ../initramfs.cpio
popd &>/dev/null

# Build kernel.
echo "Building kernel..."
make -j vmlinux
cp vmlinux "$TEST_RESOURCE_DIR/vmlinux-hello-busybox"

echo "Done!"

exit 0
