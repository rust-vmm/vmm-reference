// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

//! Reference VMM build with rust-vmm components and minimal glue.
#![deny(missing_docs)]
#![allow(dead_code, unused)]

extern crate libc;

extern crate event_manager;
extern crate kvm_bindings;
extern crate kvm_ioctls;
extern crate linux_loader;
extern crate vm_memory;
extern crate vmm_sys_util;

use std::convert::TryFrom;
use std::path::PathBuf;

use kvm_ioctls::{Kvm, VmFd};

#[derive(Default)]
/// Guest memory configurations.
pub struct MemoryConfig {
    /// Guest memory size in MiB.
    pub mem_size_mib: u32,
}

#[derive(Default)]
/// vCPU configurations.
pub struct VcpuConfig {
    /// Number of vCPUs.
    pub num_vcpus: u8,
}

#[derive(Default)]
/// Guest kernel configurations.
pub struct KernelConfig {
    /// Path to the kernel image.
    pub path: PathBuf,
    /// Start address for high memory.
    pub himem_start: u64,
}

#[derive(Default)]
/// VMM configuration.
pub struct VMMConfig {
    /// Guest memory configuration.
    pub memory_config: MemoryConfig,
    /// vCPU configuration.
    pub vcpu_config: VcpuConfig,
    /// Guest kernel configuration.
    pub kernel_config: KernelConfig,
}

#[derive(Debug)]
/// VMM errors.
pub enum Error {
    /// Placeholder.
    TODO,
}

/// Dedicated [`Result`](https://doc.rust-lang.org/std/result/) type.
pub type Result<T> = std::result::Result<T, Error>;

/// A live VMM.
pub struct VMM {
    vm_fd: VmFd,
    kvm: Kvm,
}

impl VMM {
    /// Create a new VMM.
    pub fn new() -> Result<Self> {
        unimplemented!();
    }

    /// Configure guest memory.
    ///
    /// # Arguments
    ///
    /// * `guest_mem_cfg` - [`MemoryConfig`](struct.MemoryConfig.html) struct containing guest
    ///                     memory configurations.
    pub fn configure_guest_memory(&mut self, guest_mem_cfg: MemoryConfig) -> Result<()> {
        unimplemented!();
    }

    /// Configure guest vCPUs.
    ///
    /// # Arguments
    ///
    /// * `vcpu_cfg` - [`VcpuConfig`](struct.VcpuConfig.html) struct containing vCPU configurations.
    pub fn configure_vcpus(&mut self, vcpu_cfg: VcpuConfig) -> Result<()> {
        unimplemented!();
    }

    /// Configure guest kernel.
    ///
    /// # Arguments
    ///
    /// * `kernel_cfg` - [`KernelConfig`](struct.KernelConfig.html) struct containing kernel
    ///                  configurations.
    pub fn configure_kernel(&mut self, kernel_cfg: KernelConfig) -> Result<()> {
        unimplemented!();
    }

    /// Configure PIO devices.
    ///
    /// This sets up the following PIO devices:
    /// * `x86_64`: serial console
    /// * `aarch64`: N/A
    pub fn configure_pio_devices(&mut self) -> Result<()> {
        unimplemented!();
    }

    /// Run the VMM.
    pub fn run(&self) {
        unimplemented!();
    }
}

impl TryFrom<VMMConfig> for VMM {
    type Error = Error;

    fn try_from(config: VMMConfig) -> Result<Self> {
        let mut vmm = VMM::new()?;
        vmm.configure_guest_memory(config.memory_config)?;
        vmm.configure_vcpus(config.vcpu_config)?;
        vmm.configure_kernel(config.kernel_config)?;
        vmm.configure_pio_devices()?;
        Ok(vmm)
    }
}
