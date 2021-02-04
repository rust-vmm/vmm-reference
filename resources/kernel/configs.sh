#!/bin/bash

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

# This scripts determines the busybox version to be used based on the
# current glibc version (1.32.1 for glibc version > 2.31)
# Also kernel version and config parameters are exported from here.

KERNEL_VERSION="4.14.176"
KERNEL_CFG="microvm-kernel-initramfs-hello-x86_64.config"


cat > glibc_ver.c << EOF
#include <stdio.h>
#include <gnu/libc-version.h>
int main (void) { puts (gnu_get_libc_version ()); return 0; }

EOF

GLIBC_VER=`gcc -o glibc_ver glibc_ver.c 2>/dev/null && ./glibc_ver 2>/dev/null`

#Delete the files generated
rm -f glibc_ver* 2> /dev/null

if [[ -z $GLIBC_VER ]]; then
	echo "Unable to determine glibc version, using default Busybox: 1.26."
	BUSYBOX_CFG="busybox_1_26_static_config"
	BUSYBOX_VERSION="1.26.0"
else
	if [[ $GLIBC_VER < 2.31 ]]; then
		BUSYBOX_CFG="busybox_1_26_static_config"
		BUSYBOX_VERSION="1.26.0"
	else
		BUSYBOX_CFG="busybox_1_32_1_static_config"
		BUSYBOX_VERSION="1.32.1"
	fi

fi

echo "Busybox Version: $BUSYBOX_VERSION"
echo "Config: $BUSYBOX_CFG"
