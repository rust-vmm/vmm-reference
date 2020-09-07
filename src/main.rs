// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]
#![allow(unused)]

extern crate vmm;

use std::convert::TryFrom;
use std::path::PathBuf;

use vmm::{KernelConfig, MemoryConfig, VMMConfig, VcpuConfig, VMM};

fn default_memory_config() -> MemoryConfig {
    MemoryConfig { mem_size_mib: 1024 }
}

fn default_kernel_config() -> KernelConfig {
    KernelConfig {
        path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources/kernel/vmlinux-hello-busybox"),
        himem_start: 0x0010_0000, // 1 MB
        cmdline: "console=ttyS0 i8042.nokbd reboot=k panic=1 pci=off".to_string(),
    }
}

fn default_vcpu_config() -> VcpuConfig {
    VcpuConfig { num_vcpus: 2 }
}

fn main() {
    let vmm_config = VMMConfig {
        memory_config: default_memory_config(),
        kernel_config: default_kernel_config(),
        vcpu_config: default_vcpu_config(),
    };

    let vmm = VMM::try_from(vmm_config).expect("Failed to create VMM from configurations");
    vmm.run();
}
