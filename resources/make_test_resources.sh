#!/bin/bash

# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

# This script illustrates the build steps for all the kernel and disk images
# used by tests in vmm-reference.

set -e

SOURCE=$(readlink -f "$0")
TEST_RESOURCE_DIR="$(dirname "$SOURCE")"
cd $TEST_RESOURCE_DIR

# If user doesn't provide a value for a variable, use the default one (which is
# the one used by the tests).
KERNEL_DIR=${KERNEL_DIR:="/tmp/vmlinux_busybox"}
DEB_DIR=${DEB_DIR:="/tmp/ubuntu-focal"}
DISK_DIR=${DISK_DIR:="/tmp/ubuntu-focal-disk"}

arch=$(uname -i)
if [[ $arch = "x86_64" ]]; then
    ./kernel/make_kernel_busybox_image.sh -f elf -k vmlinux-hello-busybox -w $KERNEL_DIR -j 2
    ./kernel/make_kernel_busybox_image.sh -f elf -k vmlinux-hello-busybox -w $KERNEL_DIR -j 2 -h
    ./kernel/make_kernel_busybox_image.sh -f bzimage -k bzimage-hello-busybox -w $KERNEL_DIR -j 2
    ./kernel/make_kernel_busybox_image.sh -f bzimage -k bzimage-hello-busybox -w $KERNEL_DIR -j 2 -h
    ./kernel/make_kernel_image_deb.sh -f elf -k vmlinux-focal -w $DEB_DIR -j 2
    ./kernel/make_kernel_image_deb.sh -f elf -k vmlinux-focal -w $DEB_DIR -j 2 -h
    ./kernel/make_kernel_image_deb.sh -f bzimage -k bzimage-focal -w $DEB_DIR -j 2
    ./kernel/make_kernel_image_deb.sh -f bzimage -k bzimage-focal -w $DEB_DIR -j 2 -h
    ./disk/make_rootfs.sh -d /tmp/ubuntu-focal/linux-5.4.81/deb/ -w $DISK_DIR -o rootfs.ext4
elif [[ $arch = "aarch64" ]]; then
    ./kernel/make_kernel_busybox_image.sh -f pe -k pe-hello-busybox -w $KERNEL_DIR -j 2
    ./kernel/make_kernel_busybox_image.sh -f pe -k pe-hello-busybox -w $KERNEL_DIR -j 2 -h
fi
