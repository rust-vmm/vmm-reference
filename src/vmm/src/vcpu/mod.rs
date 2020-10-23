// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::io::{self, stdin};
use std::result;
use std::sync::Arc;

use kvm_bindings::{kvm_fpu, kvm_regs, CpuId, Msrs};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use linux_loader::loader::KernelLoaderResult;
use vm_device::bus::PioAddress;
use vm_device::device_manager::{IoManager, PioManager};
use vm_memory::{Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap};
use vmm_sys_util::terminal::Terminal;

pub(crate) mod cpuid;
mod gdt;
use gdt::*;
mod interrupts;
use interrupts::*;
pub(crate) mod mpspec;
pub(crate) mod mptable;
pub(crate) mod msr_index;
pub(crate) mod msrs;

/// Initial stack for the boot CPU.
const BOOT_STACK_POINTER: u64 = 0x8ff0;

// Initial pagetables.
const PML4_START: u64 = 0x9000;
const PDPTE_START: u64 = 0xa000;
const PDE_START: u64 = 0xb000;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

/// Errors encountered during vCPU operation.
#[derive(Debug)]
pub enum Error {
    /// Failed to operate on guest memory.
    GuestMemory(GuestMemoryError),
    /// I/O Error.
    IO(io::Error),
    /// Error issuing an ioctl to KVM.
    KvmIoctl(kvm_ioctls::Error),
    /// Failed to configure mptables.
    Mptable(mptable::Error),
    /// Address stored in the rip registry does not fit in guest memory.
    RipOutOfGuestMemory,
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
    id: u8,
    /// KVM file descriptor for a vCPU.
    pub vcpu_fd: VcpuFd,
    /// Device manager for bus accesses.
    pub device_mgr: Arc<IoManager>,
}

impl Vcpu {
    /// Create a new vCPU.
    pub fn new(vm_fd: &VmFd, index: u8, device_mgr: Arc<IoManager>) -> Result<Self> {
        Ok(Vcpu {
            id: index,
            vcpu_fd: vm_fd.create_vcpu(index).map_err(Error::KvmIoctl)?,
            device_mgr,
        })
    }

    pub fn id(&self) -> u8 {
        self.id
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

    /// Configure regs.
    pub fn configure_regs(
        &self,
        kernel_load: &KernelLoaderResult,
        guest_memory: &GuestMemoryMmap,
    ) -> Result<()> {
        // If the kernel format is bzImage, the real-mode code is offset by
        // 0x200, so that's where we have to point the rip register for the
        // first instructions to execute.
        // See https://www.kernel.org/doc/html/latest/x86/boot.html#memory-layout
        //
        // The kernel is a bzImage kernel if the protocol >= 2.00 and the 0x01
        // bit (LOAD_HIGH) in the loadflags field is set.
        let mut rip = guest_memory
            .check_address(kernel_load.kernel_load)
            .ok_or(Error::RipOutOfGuestMemory)?;
        if let Some(hdr) = kernel_load.setup_header {
            if hdr.version >= 0x200 && hdr.loadflags & 0x1 == 0x1 {
                // Yup, it's bzImage.
                rip = guest_memory
                    .checked_offset(rip, 0x200)
                    .ok_or(Error::RipOutOfGuestMemory)?;
            }
        }

        let regs = kvm_regs {
            // EFLAGS (RFLAGS in 64-bit mode) always has bit 1 set.
            // See https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf#page=79
            // Section "EFLAGS Register"
            rflags: 0x0000_0000_0000_0002u64,
            rip: rip.raw_value(),
            // Starting stack pointer.
            rsp: BOOT_STACK_POINTER,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rbp: BOOT_STACK_POINTER,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: crate::ZEROPG_START,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs).map_err(Error::KvmIoctl)
    }

    /// Configure sregs.
    pub fn configure_sregs(&self, guest_memory: &GuestMemoryMmap) -> Result<()> {
        let mut sregs = self.vcpu_fd.get_sregs().map_err(Error::KvmIoctl)?;

        // Global descriptor tables.
        let gdt_table: [u64; BOOT_GDT_MAX as usize] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];

        let code_seg = kvm_segment_from_gdt(gdt_table[1], 1);
        let data_seg = kvm_segment_from_gdt(gdt_table[2], 2);
        let tss_seg = kvm_segment_from_gdt(gdt_table[3], 3);

        // Write segments to guest memory.
        write_gdt_table(&gdt_table[..], guest_memory).map_err(Error::GuestMemory)?;
        sregs.gdt.base = BOOT_GDT_OFFSET as u64;
        sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

        write_idt_value(0, guest_memory).map_err(Error::GuestMemory)?;
        sregs.idt.base = BOOT_IDT_OFFSET as u64;
        sregs.idt.limit = std::mem::size_of::<u64>() as u16 - 1;

        sregs.cs = code_seg;
        sregs.ds = data_seg;
        sregs.es = data_seg;
        sregs.fs = data_seg;
        sregs.gs = data_seg;
        sregs.ss = data_seg;
        sregs.tr = tss_seg;

        // 64-bit protected mode.
        sregs.cr0 |= X86_CR0_PE;
        sregs.efer |= (msr_index::EFER_LME | msr_index::EFER_LMA) as u64;

        // Start page table configuration.
        // Puts PML4 right after zero page but aligned to 4k.
        let boot_pml4_addr = GuestAddress(PML4_START);
        let boot_pdpte_addr = GuestAddress(PDPTE_START);
        let boot_pde_addr = GuestAddress(PDE_START);

        // Entry covering VA [0..512GB).
        guest_memory
            .write_obj(boot_pdpte_addr.raw_value() | 0x03, boot_pml4_addr)
            .map_err(Error::GuestMemory)?;

        // Entry covering VA [0..1GB).
        guest_memory
            .write_obj(boot_pde_addr.raw_value() | 0x03, boot_pdpte_addr)
            .map_err(Error::GuestMemory)?;

        // 512 2MB entries together covering VA [0..1GB).
        // This assumes that the CPU supports 2MB pages (/proc/cpuinfo has 'pse').
        for i in 0..512 {
            guest_memory
                .write_obj((i << 21) + 0x83u64, boot_pde_addr.unchecked_add(i * 8))
                .map_err(Error::GuestMemory)?;
        }

        sregs.cr3 = boot_pml4_addr.raw_value();
        sregs.cr4 |= X86_CR4_PAE;
        sregs.cr0 |= X86_CR0_PG;

        self.vcpu_fd.set_sregs(&sregs).map_err(Error::KvmIoctl)
    }

    /// Configure FPU.
    pub fn configure_fpu(&self) -> Result<()> {
        let fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        self.vcpu_fd.set_fpu(&fpu).map_err(Error::KvmIoctl)
    }

    /// Configures LAPICs. LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
    pub fn configure_lapic(&self) -> Result<()> {
        let mut klapic = self.vcpu_fd.get_lapic().map_err(Error::KvmIoctl)?;

        let lvt_lint0 = get_klapic_reg(&klapic, APIC_LVT0);
        set_klapic_reg(
            &mut klapic,
            APIC_LVT0,
            set_apic_delivery_mode(lvt_lint0, APIC_MODE_EXTINT),
        );
        let lvt_lint1 = get_klapic_reg(&klapic, APIC_LVT1);
        set_klapic_reg(
            &mut klapic,
            APIC_LVT1,
            set_apic_delivery_mode(lvt_lint1, APIC_MODE_NMI),
        );

        self.vcpu_fd.set_lapic(&klapic).map_err(Error::KvmIoctl)
    }

    /// vCPU emulation loop.
    #[allow(clippy::if_same_then_else)]
    pub fn run(&mut self) {
        match self.vcpu_fd.run() {
            Ok(exit_reason) => {
                match exit_reason {
                    VcpuExit::Shutdown | VcpuExit::Hlt => {
                        println!("Guest shutdown: {:?}. Bye!", exit_reason);
                        if stdin().lock().set_canon_mode().is_err() {
                            eprintln!("Failed to set canon mode. Stdin will not echo.");
                        }
                        unsafe { libc::exit(0) };
                    }
                    VcpuExit::IoOut(addr, data) => {
                        if 0x3f8 <= addr && addr < (0x3f8 + 8) {
                            // Write at the serial port.
                            if self.device_mgr.pio_write(PioAddress(addr), data).is_err() {
                                eprintln!("Failed to write to serial port");
                            }
                        } else if addr == 0x060 || addr == 0x061 || addr == 0x064 {
                            // Write at the i8042 port.
                            // See https://wiki.osdev.org/%228042%22_PS/2_Controller#PS.2F2_Controller_IO_Ports
                        } else if 0x070 <= addr && addr <= 0x07f {
                            // Write at the RTC port.
                        } else {
                            // Write at some other port.
                        }
                    }
                    VcpuExit::IoIn(addr, data) => {
                        if 0x3f8 <= addr && addr < (0x3f8 + 8) {
                            // Read from the serial port.
                            if self.device_mgr.pio_read(PioAddress(addr), data).is_err() {
                                eprintln!("Failed to read from serial port");
                            }
                        } else {
                            // Read from some other port.
                        }
                    }
                    _ => {
                        // Unhandled KVM exit.
                    }
                }
            }
            Err(e) => eprintln!("Emulation error: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kvm_bindings::kvm_regs;
    use kvm_ioctls::Kvm;
    use linux_loader::bootparam::setup_header;
    use linux_loader::loader::elf::PvhBootCapability;
    use linux_loader::loader::KernelLoaderResult;
    use vm_device::device_manager::IoManager;
    use vm_memory::{Address, GuestAddress, GuestMemoryMmap};

    const MEM_SIZE: usize = 0x4000_0000; // 1 GiB.

    #[test]
    fn test_configure_regs() {
        let kvm = Kvm::new().unwrap();
        let vm_fd = kvm.create_vm().unwrap();
        let vcpu = Vcpu::new(&vm_fd, 0, Arc::new(IoManager::new())).unwrap();
        let guest_memory = GuestMemoryMmap::from_ranges(&[(GuestAddress(0x0), MEM_SIZE)]).unwrap();

        // ELF (vmlinux) kernel scenario: happy case
        let mut kern_load = KernelLoaderResult {
            kernel_load: GuestAddress(0x0100_0000), // 1 MiB.
            kernel_end: 0x0223_B000,                // 1 MiB + size of a vmlinux test image.
            setup_header: None,
            pvh_boot_cap: PvhBootCapability::PvhEntryNotPresent,
        };
        assert!(vcpu.configure_regs(&kern_load, &guest_memory).is_ok());

        let expected_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: kern_load.kernel_load.raw_value(),
            rsp: BOOT_STACK_POINTER,
            rbp: BOOT_STACK_POINTER,
            rsi: crate::ZEROPG_START,
            ..Default::default()
        };
        let actual_regs = vcpu.vcpu_fd.get_regs().unwrap();
        assert_eq!(expected_regs, actual_regs);

        // ELF kernel scenario: error case (kernel load address past guest memory)
        kern_load.kernel_load = GuestAddress(guest_memory.last_addr().raw_value() + 1);

        assert!(matches!(
            vcpu.configure_regs(&kern_load, &guest_memory),
            Err(Error::RipOutOfGuestMemory)
        ));

        // bzImage kernel scenario: happy case
        // The difference is that kernel_load.setup_header is no longer None, because we found one
        // while parsing the bzImage file.
        kern_load.kernel_load = GuestAddress(0x0100_0000); // 1 MiB.
        kern_load.setup_header = Some(setup_header {
            version: 0x0200, // 0x200 (v2.00) is the minimum.
            loadflags: 1,
            ..Default::default()
        });
        assert!(vcpu.configure_regs(&kern_load, &guest_memory).is_ok());

        let expected_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: kern_load.kernel_load.unchecked_add(0x200).raw_value(),
            rsp: BOOT_STACK_POINTER,
            rbp: BOOT_STACK_POINTER,
            rsi: crate::ZEROPG_START,
            ..Default::default()
        };

        let actual_regs = vcpu.vcpu_fd.get_regs().unwrap();
        assert_eq!(expected_regs, actual_regs);

        // bzImage kernel scenario: error case: kernel_load + 0x200 (512 - size of bzImage header)
        // falls out of guest memory
        kern_load.kernel_load = GuestAddress(guest_memory.last_addr().raw_value() - 511);

        assert!(matches!(
            vcpu.configure_regs(&kern_load, &guest_memory),
            Err(Error::RipOutOfGuestMemory)
        ));
    }
}
