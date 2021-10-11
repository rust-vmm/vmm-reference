#!/bin/bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

# This scripts determines the busybox version to be used based on the
# current glibc version (1.32.1 for glibc version > 2.31)
# Also kernel version and config parameters are exported from here.

arch=$(uname -i)
KERNEL_VERSION="5.4.81"

if [[ $arch = "x86_64" ]]; then
	KERNEL_CFG="microvm-kernel-initramfs-hello-x86_64.config"
elif [[ $arch = "aarch64" ]]; then
	KERNEL_CFG="microvm-kernel-initramfs-hello-aarch64.config"
fi

BUSYBOX_CFG="busybox_1_32_1_static_config"
BUSYBOX_VERSION="1.32.1"

echo "Busybox Version: $BUSYBOX_VERSION"
echo "Config: $BUSYBOX_CFG"
