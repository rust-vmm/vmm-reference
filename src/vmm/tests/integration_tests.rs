// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

use std::convert::TryFrom;
use std::path::PathBuf;

use utils::resource_download::s3_download;
use vmm::{KernelConfig, MemoryConfig, VMMConfig, VcpuConfig, Vmm};

fn default_memory_config() -> MemoryConfig {
    MemoryConfig { size_mib: 1024 }
}

fn default_kernel_config(path: PathBuf) -> KernelConfig {
    KernelConfig {
        path,
        himem_start: 0x0010_0000, // 1 MB
        cmdline: "console=ttyS0 i8042.nokbd reboot=t panic=1 pci=off".to_string(),
    }
}

fn default_vcpu_config() -> VcpuConfig {
    VcpuConfig { num: 1 }
}

fn run_vmm(kernel_path: PathBuf) {
    let vmm_config = VMMConfig {
        kernel_config: default_kernel_config(kernel_path),
        memory_config: default_memory_config(),
        vcpu_config: default_vcpu_config(),
        block_config: None,
        net_config: None,
    };

    let mut vmm = Vmm::try_from(vmm_config).unwrap();
    vmm.run().unwrap();
}

#[test]
fn test_dummy_vmm_elf() {
    let tags = r#"
    {
        "halt_after_boot": true,
        "image_format": "elf"
    }
    "#;

    let elf_halt = s3_download("kernel", Some(tags)).unwrap();
    run_vmm(elf_halt);
}

#[test]
fn test_dummy_vmm_bzimage() {
    let tags = r#"
    {
        "halt_after_boot": true,
        "image_format": "bzimage"
    }
    "#;
    let bzimage_halt = s3_download("kernel", Some(tags)).unwrap();
    run_vmm(bzimage_halt);
}
