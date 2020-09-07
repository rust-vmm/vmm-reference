// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::result;
use std::sync::Arc;

use kvm_bindings::{CpuId, Msrs};
use kvm_ioctls::{VcpuFd, VmFd};
use vm_device::bus::PioAddress;
use vm_device::device_manager::{IoManager, PioManager};

pub(crate) mod cpuid;
pub(crate) mod mpspec;
pub(crate) mod mptable;
pub(crate) mod msr_index;
pub(crate) mod msrs;

/// Errors encountered during vCPU operation.
#[derive(Debug)]
pub enum Error {
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// Failed to configure mptables.
    Mptable(mptable::Error),
    /// Failed to configure MSRs.
    SetModelSpecificRegistersCount,
}

/// Dedicated Result type.
pub type Result<T> = result::Result<T, Error>;

/// Struct for interacting with vCPUs.
///
/// This struct is a temporary (and quite terrible) placeholder until the
/// [`vmm-vcpu`](https://github.com/rust-vmm/vmm-vcpu) crate is stabilized.
pub(crate) struct Vcpu {
    /// Index.
    pub index: u8,
    /// KVM file descriptor for a vCPU.
    pub vcpu_fd: VcpuFd,
    /// Device manager for bus accesses.
    pub device_mgr: Arc<IoManager>,
}

impl Vcpu {
    /// Create a new vCPU.
    pub fn new(vm_fd: &VmFd, index: u8, device_mgr: Arc<IoManager>) -> Result<Self> {
        Ok(Vcpu {
            index,
            vcpu_fd: vm_fd.create_vcpu(index).map_err(Error::KvmIoctl)?,
            device_mgr,
        })
    }

    /// Set CPUID.
    pub fn configure_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        self.vcpu_fd.set_cpuid2(cpuid).map_err(Error::KvmIoctl)
    }

    /// Configure MSRs.
    pub fn configure_msrs(&self) -> Result<()> {
        let entry_vec = msrs::create_boot_msr_entries();
        let msrs = Msrs::from_entries(&entry_vec);
        self.vcpu_fd
            .set_msrs(&msrs)
            .map_err(Error::KvmIoctl)
            .and_then(|msrs_written| {
                if msrs_written as u32 != msrs.as_fam_struct_ref().nmsrs {
                    Err(Error::SetModelSpecificRegistersCount)
                } else {
                    Ok(())
                }
            })
    }
}
