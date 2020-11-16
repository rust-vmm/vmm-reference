// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{Kvm, VmFd};
use vm_device::device_manager::IoManager;
use vm_memory::{Address, GuestMemory, GuestMemoryRegion};
use vmm_sys_util::eventfd::EventFd;

use crate::vcpu::{self, mptable, KvmVcpu, VcpuState};

/// Defines the state from which a `KvmVm` is initialized.
pub struct VmState {
    pub num_vcpus: u8,
}

/// A KVM specific implementation of a Virtual Machine.
///
/// Provides abstractions for working with a VM. Once a generic Vm trait will be available,
/// this type will become on of the concrete implementations.
pub struct KvmVm {
    fd: VmFd,
    state: VmState,
    // Only one of `vcpus` or `vcpu_handles` can be active at a time.
    // To create the `vcpu_handles` the `vcpu` vector is drained.
    // A better abstraction should be used to represent this behavior.
    vcpus: Vec<KvmVcpu>,
    vcpu_handles: Vec<JoinHandle<KvmVcpu>>,
}

#[derive(Debug)]
pub enum Error {
    /// Failed to create a VM.
    CreateVm(kvm_ioctls::Error),
    /// Failed to setup the user memory regions.
    SetupMemoryRegion(kvm_ioctls::Error),
    /// Not enough memory slots.
    NotEnoughMemorySlots,
    /// Failed to setup the interrupt controller.
    SetupInterruptController(kvm_ioctls::Error),
    /// Failed to create the vcpu.
    CreateVcpu(vcpu::Error),
    /// Failed to register IRQ event.
    RegisterIrqEvent(kvm_ioctls::Error),
    /// Failed to run the vcpus.
    RunVcpus(io::Error),
    /// Failed to configure mptables.
    Mptable(mptable::Error),
}

// TODO: Implement std::error::Error for Error.

/// Dedicated [`Result`](https://doc.rust-lang.org/std/result/) type.
pub type Result<T> = std::result::Result<T, Error>;

impl KvmVm {
    /// Create a new `KvmVm`.
    pub fn new<M: GuestMemory>(kvm: &Kvm, vm_state: VmState, guest_memory: &M) -> Result<Self> {
        let vm_fd = kvm.create_vm().map_err(Error::CreateVm)?;

        let vm = KvmVm {
            state: vm_state,
            fd: vm_fd,
            vcpus: Vec::new(),
            vcpu_handles: Vec::new(),
        };

        vm.configure_memory_regions(guest_memory, kvm)?;

        mptable::setup_mptable(guest_memory, vm.state.num_vcpus).map_err(Error::Mptable)?;

        vm.setup_irq_controller()?;

        Ok(vm)
    }

    // Create the kvm memory regions based on the configuration passed as `guest_memory`.
    fn configure_memory_regions<M: GuestMemory>(&self, guest_memory: &M, kvm: &Kvm) -> Result<()> {
        if guest_memory.num_regions() > kvm.get_nr_memslots() {
            return Err(Error::NotEnoughMemorySlots);
        }

        // Register guest memory regions with KVM.
        guest_memory
            .with_regions(|index, region| {
                let memory_region = kvm_userspace_memory_region {
                    slot: index as u32,
                    guest_phys_addr: region.start_addr().raw_value(),
                    memory_size: region.len() as u64,
                    // It's safe to unwrap because the guest address is valid.
                    userspace_addr: guest_memory.get_host_address(region.start_addr()).unwrap()
                        as u64,
                    flags: 0,
                };

                // Safe because:
                // * userspace_addr is a valid address for a memory region, obtained by calling
                //   get_host_address() on a valid region's start address;
                // * the memory regions do not overlap - there's either a single region spanning
                //   the whole guest memory, or 2 regions with the MMIO gap in between.
                unsafe { self.fd.set_user_memory_region(memory_region) }
            })
            .map_err(Error::SetupMemoryRegion)?;

        Ok(())
    }

    // Configures the in kernel interrupt controller.
    // This function should be reused to configure the aarch64 interrupt controller (GIC).
    fn setup_irq_controller(&self) -> Result<()> {
        // First, create the irqchip.
        // On `x86_64`, this _must_ be created _before_ the vCPUs.
        // It sets up the virtual IOAPIC, virtual PIC, and sets up the future vCPUs for local APIC.
        // When in doubt, look in the kernel for `KVM_CREATE_IRQCHIP`.
        // https://elixir.bootlin.com/linux/latest/source/arch/x86/kvm/x86.c
        self.fd
            .create_irq_chip()
            .map_err(Error::SetupInterruptController)?;

        // The PIT is used during boot to configure the frequency.
        // The output from PIT channel 0 is connected to the PIC chip, so that it
        // generates an "IRQ 0" (system timer).
        // https://wiki.osdev.org/Programmable_Interval_Timer
        let mut pit_config = kvm_pit_config::default();
        // Set up the speaker PIT, because some kernels are musical and access the speaker port
        // during boot. Without this, KVM would continuously exit to userspace.
        pit_config.flags = KVM_PIT_SPEAKER_DUMMY;
        self.fd
            .create_pit2(pit_config)
            .map_err(Error::SetupInterruptController)
    }

    /// Create a Vcpu based on the passed configuration.
    pub fn create_vcpu<M: GuestMemory>(
        &mut self,
        bus: Arc<IoManager>,
        vcpu_state: VcpuState,
        memory: &M,
    ) -> Result<()> {
        let vcpu = KvmVcpu::new(&self.fd, bus, vcpu_state, memory).map_err(Error::CreateVcpu)?;
        self.vcpus.push(vcpu);
        Ok(())
    }

    /// Let KVM know that instead of triggering an actual interrupt for `irq_number`, we will
    /// just write on the specified `event`.
    pub fn register_irqfd(&self, event: &EventFd, irq_number: u32) -> Result<()> {
        self.fd
            .register_irqfd(&event, irq_number)
            .map_err(Error::RegisterIrqEvent)
    }

    /// Run the `Vm` based on the passed `vcpu` configuration.
    ///
    /// When no vcpus are created, the function has no side effects.
    pub fn run(&mut self) -> Result<()> {
        for mut vcpu in self.vcpus.drain(..) {
            let vcpu_handle: JoinHandle<KvmVcpu> = thread::Builder::new()
                .spawn(move || loop {
                    vcpu.run();
                })
                .map_err(Error::RunVcpus)?;
            self.vcpu_handles.push(vcpu_handle);
        }

        Ok(())
    }
}
