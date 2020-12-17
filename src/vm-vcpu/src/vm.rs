// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::io::{self, ErrorKind};
use std::sync::{Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};

use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{Kvm, VmFd};
use vm_device::device_manager::IoManager;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion};
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
pub struct KvmVm<EH: ExitHandler + Send> {
    fd: Arc<VmFd>,
    state: VmState,
    // Only one of `vcpus` or `vcpu_handles` can be active at a time.
    // To create the `vcpu_handles` the `vcpu` vector is drained.
    // A better abstraction should be used to represent this behavior.
    vcpus: Vec<KvmVcpu>,
    vcpu_handles: Vec<JoinHandle<()>>,
    exit_handler: EH,
    vcpu_barrier: Arc<Barrier>,
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

/// Trait that allows the VM to signal that the VCPUs have exited.
///
// This trait needs Clone because each VCPU needs to be able to call the `kick` function.
pub trait ExitHandler: Clone {
    fn kick(&self) -> io::Result<()>;
}

impl<EH: 'static + ExitHandler + Send> KvmVm<EH> {
    /// Create a new `KvmVm`.
    pub fn new<M: GuestMemory>(
        kvm: &Kvm,
        vm_state: VmState,
        guest_memory: &M,
        exit_handler: EH,
    ) -> Result<Self> {
        let vm_fd = Arc::new(kvm.create_vm().map_err(Error::CreateVm)?);

        let vm = KvmVm {
            vcpu_barrier: Arc::new(Barrier::new(vm_state.num_vcpus as usize)),
            state: vm_state,
            fd: vm_fd,
            vcpus: Vec::new(),
            vcpu_handles: Vec::new(),
            exit_handler,
        };

        vm.configure_memory_regions(guest_memory, kvm)?;

        mptable::setup_mptable(guest_memory, vm.state.num_vcpus).map_err(Error::Mptable)?;

        vm.setup_irq_controller()?;

        Ok(vm)
    }

    /// Retrieve the associated KVM VM file descriptor.
    pub fn vm_fd(&self) -> Arc<VmFd> {
        self.fd.clone()
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
        bus: Arc<Mutex<IoManager>>,
        vcpu_state: VcpuState,
        memory: &M,
    ) -> Result<()> {
        let vcpu = KvmVcpu::new(&self.fd, bus, vcpu_state, self.vcpu_barrier.clone(), memory)
            .map_err(Error::CreateVcpu)?;
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
    /// Returns an error when the number of configured vcpus is not the same as the number
    /// of created vcpus (using the `create_vcpu` function).
    ///
    /// # Arguments
    ///
    /// * `vcpu_run_addr`: address in guest memory where the vcpu run starts.
    pub fn run(&mut self, vcpu_run_addr: GuestAddress) -> Result<()> {
        if self.vcpus.len() != self.state.num_vcpus as usize {
            return Err(Error::RunVcpus(io::Error::from(ErrorKind::InvalidInput)));
        }

        for mut vcpu in self.vcpus.drain(..) {
            let vcpu_exit_handler = self.exit_handler.clone();
            let vcpu_handle = thread::Builder::new()
                .spawn(move || {
                    // TODO: Check the result of both vcpu run & kick.
                    let _ = vcpu.run(vcpu_run_addr);
                    let _ = vcpu_exit_handler.kick();
                })
                .map_err(Error::RunVcpus)?;
            self.vcpu_handles.push(vcpu_handle);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::vcpu::mptable::MAX_SUPPORTED_CPUS;
    use crate::vm::{Error, KvmVm, VmState};

    use std::sync::atomic::{AtomicBool, Ordering};

    use kvm_bindings::CpuId;
    use kvm_ioctls::Kvm;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    #[derive(Clone, Default)]
    struct WrappedExitHandler(Arc<DummyExitHandler>);

    #[derive(Default)]
    struct DummyExitHandler {
        kicked: AtomicBool,
    }

    impl ExitHandler for WrappedExitHandler {
        fn kick(&self) -> io::Result<()> {
            self.0.kicked.store(true, Ordering::Release);
            Ok(())
        }
    }

    // A helper function that creates a KvmVm with a default memory configuration.
    fn default_vm(num_vcpus: u8) -> Result<(KvmVm<WrappedExitHandler>, GuestMemoryMmap)> {
        let kvm = Kvm::new().unwrap();

        let vm_state = VmState { num_vcpus };

        let mem_size = (128 << 20) as usize;
        let guest_memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), mem_size)]).unwrap();
        let exit_handler = WrappedExitHandler::default();
        let vm = KvmVm::new(&kvm, vm_state, &guest_memory, exit_handler)?;
        Ok((vm, guest_memory))
    }

    #[test]
    fn test_failed_setup_mptable() {
        let num_vcpus = (MAX_SUPPORTED_CPUS + 1) as u8;
        let res = default_vm(num_vcpus);
        assert!(matches!(res, Err(Error::Mptable(_))));
    }

    #[test]
    fn test_failed_setup_memory() {
        let kvm = Kvm::new().unwrap();
        let vm_state = VmState { num_vcpus: 1 };

        // Create nr_slots non overlapping regions of length 100.
        let nr_slots: u64 = (kvm.get_nr_memslots() + 1) as u64;
        let mut ranges = Vec::<(GuestAddress, usize)>::new();
        for i in 0..nr_slots {
            ranges.push((GuestAddress(i * 100), 100))
        }
        let guest_memory = GuestMemoryMmap::from_ranges(&ranges).unwrap();
        let res = KvmVm::new(&kvm, vm_state, &guest_memory, WrappedExitHandler::default());
        assert!(matches!(res, Err(Error::NotEnoughMemorySlots)));
    }

    #[test]
    fn test_failed_irqchip_setup() {
        let kvm = Kvm::new().unwrap();
        let vm_state = VmState { num_vcpus: 1 };

        let vm = KvmVm {
            vcpus: Vec::new(),
            vcpu_handles: Vec::new(),
            vcpu_barrier: Arc::new(Barrier::new(vm_state.num_vcpus as usize)),
            state: vm_state,
            fd: Arc::new(kvm.create_vm().unwrap()),
            exit_handler: WrappedExitHandler::default(),
        };

        // Setting up the irq_controller twice should return an error.
        vm.setup_irq_controller().unwrap();
        let res = vm.setup_irq_controller();
        assert!(matches!(res, Err(Error::SetupInterruptController(_))));
    }

    #[test]
    fn test_invalid_vcpu_run() {
        // We're specifying in the VmState that we want to run one vcpu, but we do not create
        // any. This should return an error.
        let (mut vm, _guest_memory) = default_vm(1).unwrap();
        assert!(
            matches!(vm.run(GuestAddress(0x1000_0000)), Err(Error::RunVcpus(e)) if e.kind() == ErrorKind::InvalidInput)
        );
    }

    #[test]
    fn test_create_vcpu() {
        let num_vcpus = 2;

        let (mut vm, guest_memory) = default_vm(num_vcpus).unwrap();
        let io_manager = Arc::new(Mutex::new(IoManager::new()));

        for i in 0..vm.state.num_vcpus {
            // We're creating a dummy Vcpu.
            vm.create_vcpu(
                io_manager.clone(),
                VcpuState {
                    cpuid: CpuId::new(1),
                    id: i,
                },
                &guest_memory,
            )
            .unwrap();
        }

        assert_eq!(vm.vcpus.len() as u8, num_vcpus);
        assert_eq!(vm.vcpu_handles.len() as u8, 0);
    }
}
