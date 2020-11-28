// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

use std::path::PathBuf;

use libc::fork;

use vmm::{KernelConfig, MemoryConfig, VMMConfig, VcpuConfig};

mod test_utils;
use test_utils::*;

const DEFAULT_BZIMAGE: &str = "../../resources/kernel/bzimage-hello-busybox-halt";
const DEFAULT_ELF: &str = "../../resources/kernel/vmlinux-hello-busybox-halt";

fn default_memory_config() -> MemoryConfig {
    MemoryConfig { size_mib: 1024 }
}

fn default_kernel_config(path: PathBuf) -> KernelConfig {
    KernelConfig {
        path,
        himem_start: 0x0010_0000, // 1 MB
        cmdline: "console=ttyS0 i8042.nokbd reboot=k panic=1 pci=off".to_string(),
    }
}

fn default_vcpu_config() -> VcpuConfig {
    VcpuConfig { num: 1 }
}

#[test]
fn test_dummy_vmm_elf() {
    let pid = unsafe { fork() };
    let vmm_config = VMMConfig {
        kernel_config: default_kernel_config(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_ELF),
        ),
        memory_config: default_memory_config(),
        vcpu_config: default_vcpu_config(),
        block_config: None,
        network_config: None,
    };
    // Sanity check. Because the VMM runs in a separate process, if the file doesn't exist,
    // all we see is a different exit code than 0.
    assert!(vmm_config.kernel_config.path.as_path().exists());
    run_vmm(pid, vmm_config);
}

#[test]
fn test_dummy_vmm_bzimage() {
    let pid = unsafe { fork() };
    let vmm_config = VMMConfig {
        kernel_config: default_kernel_config(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_BZIMAGE),
        ),
        memory_config: default_memory_config(),
        vcpu_config: default_vcpu_config(),
        block_config: None,
        network_config: None,
    };
    assert!(vmm_config.kernel_config.path.as_path().exists());
    run_vmm(pid, vmm_config);
}
