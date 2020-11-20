// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

//! Reference VMM built with rust-vmm components and minimal glue.
#![deny(missing_docs)]

use std::convert::TryFrom;
use std::ffi::CString;
use std::fs::File;
use std::io::{self, stdin, stdout};
use std::sync::{Arc, Mutex};

use event_manager::{EventManager, MutEventSubscriber, SubscriberOps};
use kvm_bindings::{KVM_API_VERSION, KVM_MAX_CPUID_ENTRIES};
use kvm_ioctls::{
    Cap::{self, Ioeventfd, Irqchip, Irqfd, UserMemory},
    Kvm,
};
use linux_loader::bootparam::boot_params;
use linux_loader::cmdline::{self, Cmdline};
use linux_loader::configurator::{
    self, linux::LinuxBootConfigurator, BootConfigurator, BootParams,
};
use linux_loader::loader::{
    self,
    bzimage::BzImage,
    elf::{self, Elf},
    load_cmdline, KernelLoader, KernelLoaderResult,
};
use vm_device::device_manager::IoManager;
use vm_device::resources::Resource;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap};
use vm_superio::Serial;
use vm_vcpu::vcpu::{cpuid::filter_cpuid, VcpuState};
use vm_vcpu::vm::{self, KvmVm, VmState};
use vmm_sys_util::{eventfd::EventFd, terminal::Terminal};

mod boot;
use boot::build_bootparams;

mod config;
pub use config::*;

mod devices;
use devices::SerialWrapper;

/// First address past 32 bits.
const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
/// Size of the MMIO gap.
const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
/// The start of the memory area reserved for MMIO devices.
const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// Address of the zeropage, where Linux kernel boot parameters are written.
const ZEROPG_START: u64 = 0x7000;
/// Address where the kernel command line is written.
const CMDLINE_START: u64 = 0x0002_0000;

/// Default high memory start.
pub const HIGH_RAM_START: u64 = 0x100000;

/// Default kernel command line.
pub const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 i8042.nokbd reboot=k panic=1 pci=off";

/// VMM memory related errors.
#[derive(Debug)]
pub enum MemoryError {
    /// Not enough memory slots.
    NotEnoughMemorySlots,
    /// Failed to configure guest memory.
    VmMemory(vm_memory::Error),
}

/// VMM errors.
#[derive(Debug)]
pub enum Error {
    /// Failed to write boot parameters to guest memory.
    BootConfigure(configurator::Error),
    /// Error configuring boot parameters.
    BootParam(boot::Error),
    /// Error configuring the kernel command line.
    Cmdline(cmdline::Error),
    /// Error setting up devices.
    Device(devices::Error),
    /// Event management error.
    EventManager(event_manager::Error),
    /// I/O error.
    IO(io::Error),
    /// Failed to load kernel.
    KernelLoad(loader::Error),
    /// Address stored in the rip registry does not fit in guest memory.
    RipOutOfGuestMemory,
    /// Invalid KVM API version.
    KvmApiVersion(i32),
    /// Unsupported KVM capability.
    KvmCap(Cap),
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// Memory error.
    Memory(MemoryError),
    /// VM errors.
    Vm(vm::Error),
}

impl std::convert::From<vm::Error> for Error {
    fn from(vm_error: vm::Error) -> Self {
        Self::Vm(vm_error)
    }
}

/// Dedicated [`Result`](https://doc.rust-lang.org/std/result/) type.
pub type Result<T> = std::result::Result<T, Error>;

/// A live VMM.
pub struct VMM {
    kvm: Kvm,
    vm: KvmVm,
    guest_memory: GuestMemoryMmap,
    // The `device_mgr` is an Arc<Mutex> so that it can be shared between
    // the Vcpu threads, and modified when new devices are added.
    device_mgr: Arc<Mutex<IoManager>>,
    // Arc<Mutex<>> because the same device (a dyn DevicePio/DeviceMmio from IoManager's
    // perspective, and a dyn MutEventSubscriber from EventManager's) is managed by the 2 entities,
    // and isn't Copy-able; so once one of them gets ownership, the other one can't anymore.
    event_mgr: EventManager<Arc<Mutex<dyn MutEventSubscriber>>>,
}

impl TryFrom<VMMConfig> for VMM {
    type Error = Error;

    fn try_from(config: VMMConfig) -> Result<Self> {
        let kvm = Kvm::new().map_err(Error::KvmIoctl)?;

        // Check that the KVM on the host is supported.
        let kvm_api_ver = kvm.get_api_version();
        if kvm_api_ver != KVM_API_VERSION as i32 {
            return Err(Error::KvmApiVersion(kvm_api_ver));
        }
        VMM::check_kvm_capabilities(&kvm)?;

        let guest_memory = VMM::create_guest_memory(&config.memory_config)?;

        // Create the KvmVm.
        let vm_state = VmState {
            num_vcpus: config.vcpu_config.num,
        };
        let vm = KvmVm::new(&kvm, vm_state, &guest_memory)?;

        let mut vmm = VMM {
            vm,
            kvm,
            guest_memory,
            device_mgr: Arc::new(Mutex::new(IoManager::new())),
            event_mgr: EventManager::new().map_err(Error::EventManager)?,
        };

        vmm.add_serial_console()?;
        let load_result = vmm.load_kernel(&config.kernel_config)?;
        vmm.create_vcpus(&config.vcpu_config, &load_result)?;

        Ok(vmm)
    }
}

impl VMM {
    /// Run the VMM.
    pub fn run(&mut self) -> Result<()> {
        if stdin().lock().set_raw_mode().is_err() {
            eprintln!("Failed to set raw mode on terminal. Stdin will echo.");
        }

        self.vm.run().map_err(Error::Vm)?;

        loop {
            match self.event_mgr.run() {
                Ok(_) => (),
                Err(e) => eprintln!("Failed to handle events: {:?}", e),
            }
        }
    }

    // Create guest memory regions.
    // On x86_64, they surround the MMIO gap (dedicated space for MMIO device slots) if the
    // configured memory size exceeds the latter's starting address.
    fn create_guest_memory(memory_config: &MemoryConfig) -> Result<GuestMemoryMmap> {
        let mem_size = ((memory_config.size_mib as u64) << 20) as usize;
        let mem_regions = match mem_size.checked_sub(MMIO_MEM_START as usize) {
            // Guest memory fits before the MMIO gap.
            None | Some(0) => vec![(GuestAddress(0), mem_size)],
            // Guest memory extends beyond the MMIO gap.
            Some(remaining) => vec![
                (GuestAddress(0), MMIO_MEM_START as usize),
                (GuestAddress(FIRST_ADDR_PAST_32BITS), remaining),
            ],
        };

        // Create guest memory from regions.
        GuestMemoryMmap::from_ranges(&mem_regions)
            .map_err(|e| Error::Memory(MemoryError::VmMemory(e)))
    }

    /// Load the kernel into guest memory.
    ///
    /// # Arguments
    ///
    /// * `kernel_cfg` - [`KernelConfig`](struct.KernelConfig.html) struct containing kernel
    ///                  configurations.
    fn load_kernel(&mut self, kernel_cfg: &KernelConfig) -> Result<KernelLoaderResult> {
        let mut kernel_image = File::open(&kernel_cfg.path).map_err(Error::IO)?;
        let zero_page_addr = GuestAddress(ZEROPG_START);

        // Load the kernel into guest memory.
        let kernel_load = match Elf::load(
            &self.guest_memory,
            None,
            &mut kernel_image,
            Some(GuestAddress(kernel_cfg.himem_start)),
        ) {
            Ok(result) => result,
            Err(loader::Error::Elf(elf::Error::InvalidElfMagicNumber)) => BzImage::load(
                &self.guest_memory,
                None,
                &mut kernel_image,
                Some(GuestAddress(kernel_cfg.himem_start)),
            )
            .map_err(Error::KernelLoad)?,
            Err(e) => {
                return Err(Error::KernelLoad(e));
            }
        };

        // Generate boot parameters.
        let mut bootparams = build_bootparams(
            &self.guest_memory,
            &kernel_load,
            GuestAddress(kernel_cfg.himem_start),
            GuestAddress(MMIO_MEM_START),
            GuestAddress(FIRST_ADDR_PAST_32BITS),
        )
        .map_err(Error::BootParam)?;

        // Add the kernel command line to the boot parameters.
        bootparams.hdr.cmd_line_ptr = CMDLINE_START as u32;
        bootparams.hdr.cmdline_size = kernel_cfg.cmdline.len() as u32 + 1;

        // Load the kernel command line into guest memory.
        let mut cmdline = Cmdline::new(kernel_cfg.cmdline.len() + 1);
        cmdline
            .insert_str(kernel_cfg.cmdline.clone())
            .map_err(Error::Cmdline)?;
        load_cmdline(
            &self.guest_memory,
            GuestAddress(CMDLINE_START),
            // Safe because we know the command line string doesn't contain any 0 bytes.
            unsafe { &CString::from_vec_unchecked(cmdline.into()) },
        )
        .map_err(Error::KernelLoad)?;

        // Write the boot parameters in the zeropage.
        LinuxBootConfigurator::write_bootparams::<GuestMemoryMmap>(
            &BootParams::new::<boot_params>(&bootparams, zero_page_addr),
            &self.guest_memory,
        )
        .map_err(Error::BootConfigure)?;

        Ok(kernel_load)
    }

    /// Create and add a serial console to the VMM.
    fn add_serial_console(&mut self) -> Result<()> {
        // Create the serial console.
        let interrupt_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(Error::IO)?;
        let serial = Arc::new(Mutex::new(SerialWrapper(Serial::new(
            interrupt_evt.try_clone().map_err(Error::IO)?,
            stdout(),
        ))));

        // Register its interrupt fd with KVM. IRQ line 4 is typically used for serial port 1.
        // See more IRQ assignments & info: https://tldp.org/HOWTO/Serial-HOWTO-8.html
        self.vm.register_irqfd(&interrupt_evt, 4)?;

        // Put it on the bus.
        // Safe to use expect() because the device manager is instantiated in new(), there's no
        // default implementation, and the field is private inside the VMM struct.
        self.device_mgr
            .lock()
            .unwrap()
            .register_pio_resources(
                serial.clone(),
                &[Resource::PioAddressRange {
                    base: 0x3f8,
                    size: 0x8,
                }],
            )
            .unwrap();

        // Hook it to event management.
        self.event_mgr.add_subscriber(serial);

        Ok(())
    }

    // Helper function that computes the kernel_load_addr needed by the
    // VcpuState when creating the Vcpus.
    fn compute_kernel_load_addr(&self, kernel_load: &KernelLoaderResult) -> Result<GuestAddress> {
        // If the kernel format is bzImage, the real-mode code is offset by
        // 0x200, so that's where we have to point the rip register for the
        // first instructions to execute.
        // See https://www.kernel.org/doc/html/latest/x86/boot.html#memory-layout
        //
        // The kernel is a bzImage kernel if the protocol >= 2.00 and the 0x01
        // bit (LOAD_HIGH) in the loadflags field is set.
        let mut kernel_load_addr = self
            .guest_memory
            .check_address(kernel_load.kernel_load)
            .ok_or(Error::RipOutOfGuestMemory)?;
        if let Some(hdr) = kernel_load.setup_header {
            if hdr.version >= 0x200 && hdr.loadflags & 0x1 == 0x1 {
                // Yup, it's bzImage.
                kernel_load_addr = self
                    .guest_memory
                    .checked_offset(kernel_load_addr, 0x200)
                    .ok_or(Error::RipOutOfGuestMemory)?;
            }
        }

        Ok(kernel_load_addr)
    }

    /// Create guest vCPUs.
    ///
    /// # Arguments
    ///
    /// * `vcpu_cfg` - [`VcpuConfig`] struct containing vCPU configurations.
    /// * `kernel_load` - [`KernelLoaderResult`] struct, result of loading the kernel in guest memory.
    ///
    /// [`KernelLoaderResult`]: https://docs.rs/linux-loader/latest/linux_loader/loader/struct.KernelLoaderResult.html
    /// [`VcpuConfig`]: struct.VcpuConfig.html
    fn create_vcpus(
        &mut self,
        vcpu_cfg: &VcpuConfig,
        kernel_load: &KernelLoaderResult,
    ) -> Result<()> {
        let kernel_load_addr = self.compute_kernel_load_addr(kernel_load)?;

        let base_cpuid = self
            .kvm
            .get_supported_cpuid(KVM_MAX_CPUID_ENTRIES)
            .map_err(Error::KvmIoctl)?;

        for index in 0..vcpu_cfg.num {
            // Set CPUID.
            let mut cpuid = base_cpuid.clone();
            filter_cpuid(&self.kvm, index as usize, vcpu_cfg.num as usize, &mut cpuid);

            let vcpu_state = VcpuState {
                kernel_load_addr,
                cpuid,
                id: index,
                zero_page_start: GuestAddress(ZEROPG_START),
            };
            self.vm
                .create_vcpu(self.device_mgr.clone(), vcpu_state, &self.guest_memory)?;
        }

        Ok(())
    }

    fn check_kvm_capabilities(kvm: &Kvm) -> Result<()> {
        let capabilities = vec![Irqchip, Ioeventfd, Irqfd, UserMemory];

        // Check that all desired capabilities are supported.
        if let Some(c) = capabilities
            .iter()
            .find(|&capability| !kvm.check_extension(*capability))
        {
            Err(Error::KvmCap(*c))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::ErrorKind;
    use std::path::PathBuf;

    use linux_loader::loader::bootparam::setup_header;
    use linux_loader::loader::elf::PvhBootCapability;
    use vm_memory::{Address, GuestMemory};
    use vmm_sys_util::tempfile::TempFile;

    const MEM_SIZE_MIB: u32 = 1024;
    const NUM_VCPUS: u8 = 1;
    const HIMEM_START_ADDR: u64 = 0x0010_0000; // 1 MB

    fn default_vmm_config() -> VMMConfig {
        VMMConfig {
            kernel_config: KernelConfig {
                path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../resources/kernel/vmlinux-hello-busybox"),
                himem_start: HIMEM_START_ADDR,
                cmdline: "foo=bar".to_string(),
            },
            memory_config: MemoryConfig {
                size_mib: MEM_SIZE_MIB,
            },
            vcpu_config: VcpuConfig { num: NUM_VCPUS },
        }
    }

    // Returns a VMM which only has the memory configured. The purpose of the mock VMM
    // is to give a finer grained control to test individual private functions in the VMM.
    fn mock_vmm(vmm_config: VMMConfig) -> VMM {
        let kvm = Kvm::new().unwrap();
        let guest_memory = VMM::create_guest_memory(&vmm_config.memory_config).unwrap();

        // Create the KvmVm.
        let vm_state = VmState {
            num_vcpus: vmm_config.vcpu_config.num,
        };
        let vm = KvmVm::new(&kvm, vm_state, &guest_memory).unwrap();

        VMM {
            vm,
            kvm,
            guest_memory,
            device_mgr: Arc::new(Mutex::new(IoManager::new())),
            event_mgr: EventManager::new().unwrap(),
        }
    }

    #[test]
    fn test_try_from() {
        let mut vmm_config = default_vmm_config();

        // Test happy case.
        {
            let vmm = VMM::try_from(vmm_config.clone()).unwrap();
            assert_eq!(
                vmm.guest_memory.last_addr(),
                GuestAddress(((MEM_SIZE_MIB as u64) << 20) - 1)
            );
        }

        // Error case: missing kernel file.
        {
            vmm_config.kernel_config.path = PathBuf::from(TempFile::new().unwrap().as_path());
            assert!(
                matches!(VMM::try_from(vmm_config), Err(Error::IO(e)) if e.kind() == ErrorKind::NotFound)
            );
        }
    }

    #[test]
    fn test_create_vcpus() {
        let vmm_config = default_vmm_config();
        let mut vmm = mock_vmm(vmm_config.clone());

        // ELF (vmlinux) kernel scenario: happy case
        let mut kern_load = KernelLoaderResult {
            kernel_load: GuestAddress(0x0100_0000), // 1 MiB.
            kernel_end: 0x0223_B000,                // 1 MiB + size of a vmlinux test image.
            setup_header: None,
            pvh_boot_cap: PvhBootCapability::PvhEntryNotPresent,
        };
        let actual_kernel_load_addr = vmm.compute_kernel_load_addr(&kern_load).unwrap();
        let expected_load_addr = kern_load.kernel_load;
        assert_eq!(actual_kernel_load_addr, expected_load_addr);
        assert!(vmm
            .create_vcpus(&vmm_config.vcpu_config.clone(), &kern_load)
            .is_ok());

        // ELF kernel scenario: error case (kernel load address past guest memory).
        // Since we don't need to check the load_address, we can test this directly with
        // create_vcpu.
        let mut vmm = mock_vmm(vmm_config.clone());
        kern_load.kernel_load = GuestAddress(vmm.guest_memory.last_addr().raw_value() + 1);
        assert!(matches!(
            vmm.create_vcpus(&vmm_config.vcpu_config.clone(), &kern_load),
            Err(Error::RipOutOfGuestMemory)
        ));

        // bzImage kernel scenario: happy case
        // The difference is that kernel_load.setup_header is no longer None, because we found one
        // while parsing the bzImage file.
        let mut vmm = mock_vmm(vmm_config.clone());
        kern_load.kernel_load = GuestAddress(0x0100_0000); // 1 MiB.
        kern_load.setup_header = Some(setup_header {
            version: 0x0200, // 0x200 (v2.00) is the minimum.
            loadflags: 1,
            ..Default::default()
        });
        let expected_load_addr = kern_load.kernel_load.unchecked_add(0x200);
        let actual_kernel_load_addr = vmm.compute_kernel_load_addr(&kern_load).unwrap();
        assert_eq!(expected_load_addr, actual_kernel_load_addr);
        assert!(vmm
            .create_vcpus(&vmm_config.vcpu_config.clone(), &kern_load)
            .is_ok());

        // bzImage kernel scenario: error case: kernel_load + 0x200 (512 - size of bzImage header)
        // falls out of guest memory
        let mut vmm = mock_vmm(vmm_config.clone());
        kern_load.kernel_load = GuestAddress(vmm.guest_memory.last_addr().raw_value() - 511);
        assert!(matches!(
            vmm.create_vcpus(&vmm_config.vcpu_config, &kern_load),
            Err(Error::RipOutOfGuestMemory)
        ));
    }
}
