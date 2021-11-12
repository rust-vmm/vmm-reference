// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright 2017 The Chromium OS Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use libc::siginfo_t;
use std::cell::RefCell;
use std::ffi::c_void;
use std::io::{self, stdin};
use std::os::raw::c_int;
use std::result;
use std::sync::{Arc, Barrier, Condvar, Mutex};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::{kvm_fpu, kvm_regs, CpuId};
#[cfg(target_arch = "aarch64")]
use kvm_bindings::{
    kvm_vcpu_init, KVM_SYSTEM_EVENT_CRASH, KVM_SYSTEM_EVENT_RESET, KVM_SYSTEM_EVENT_SHUTDOWN,
};
use kvm_ioctls::{VcpuExit, VcpuFd, VmFd};
use vm_device::bus::{MmioAddress, PioAddress};
use vm_device::device_manager::{IoManager, MmioManager, PioManager};
#[cfg(target_arch = "aarch64")]
use vm_memory::GuestMemoryRegion;
#[cfg(target_arch = "x86_64")]
use vm_memory::{Address, Bytes};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryError};
#[cfg(target_arch = "x86_64")]
use vm_vcpu_ref::x86_64::{
    gdt::{self, write_idt_value, Gdt, BOOT_GDT_OFFSET, BOOT_IDT_OFFSET},
    interrupts::{set_klapic_delivery_mode, APIC_LVT0, APIC_LVT1, APIC_MODE_EXTINT, APIC_MODE_NMI},
    mptable, msr_index, msrs,
};
use vmm_sys_util::errno::Error as Errno;
use vmm_sys_util::signal::{register_signal_handler, SIGRTMIN};
use vmm_sys_util::terminal::Terminal;

use utils::debug;

#[cfg(target_arch = "aarch64")]
#[macro_use]
mod regs;

#[cfg(target_arch = "aarch64")]
use regs::*;

use crate::vm::VmRunState;
#[cfg(target_arch = "aarch64")]
use arch::{AARCH64_FDT_MAX_SIZE, AARCH64_PHYS_MEM_START};

/// Initial stack for the boot CPU.
#[cfg(target_arch = "x86_64")]
const BOOT_STACK_POINTER: u64 = 0x8ff0;
/// Address of the zeropage, where Linux kernel boot parameters are written.
#[cfg(target_arch = "x86_64")]
const ZEROPG_START: u64 = 0x7000;

// Initial pagetables.
#[cfg(target_arch = "x86_64")]
mod pagetable {
    pub const PML4_START: u64 = 0x9000;
    pub const PDPTE_START: u64 = 0xa000;
    pub const PDE_START: u64 = 0xb000;
}
#[cfg(target_arch = "x86_64")]
use pagetable::*;

#[cfg(target_arch = "x86_64")]
mod regs {
    pub const X86_CR0_PE: u64 = 0x1;
    pub const X86_CR0_PG: u64 = 0x8000_0000;
    pub const X86_CR4_PAE: u64 = 0x20;
}
#[cfg(target_arch = "x86_64")]
use regs::*;

#[cfg(target_arch = "aarch64")]
use kvm_bindings::{PSR_MODE_EL1h, PSR_A_BIT, PSR_D_BIT, PSR_F_BIT, PSR_I_BIT};

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
    #[cfg(target_arch = "x86_64")]
    Mptable(mptable::Error),
    /// Failed to setup the GDT.
    #[cfg(target_arch = "x86_64")]
    Gdt(gdt::Error),
    /// Failed to initialize MSRS.
    #[cfg(target_arch = "x86_64")]
    CreateMsr(msrs::Error),
    /// Failed to configure MSRs.
    SetModelSpecificRegistersCount,
    /// TLS already initialized.
    TlsInitialized,
    /// Unable to register signal handler.
    RegisterSignalHandler(Errno),
    SetReg(kvm_ioctls::Error),
}

/// Dedicated Result type.
pub type Result<T> = result::Result<T, Error>;

pub struct VcpuState {
    pub id: u8,
    #[cfg(target_arch = "x86_64")]
    pub cpuid: CpuId,
}

/// Represents the current run state of the VCPUs.
#[derive(Default)]
pub struct VcpuRunState {
    pub(crate) vm_state: Mutex<VmRunState>,
    condvar: Condvar,
}

impl VcpuRunState {
    pub fn set_and_notify(&self, state: VmRunState) {
        *self.vm_state.lock().unwrap() = state;
        self.condvar.notify_all();
    }
}

/// Struct for interacting with vCPUs.
///
/// This struct is a temporary (and quite terrible) placeholder until the
/// [`vmm-vcpu`](https://github.com/rust-vmm/vmm-vcpu) crate is stabilized.
pub struct KvmVcpu {
    /// KVM file descriptor for a vCPU.
    vcpu_fd: VcpuFd,
    /// Device manager for bus accesses.
    device_mgr: Arc<Mutex<IoManager>>,
    state: VcpuState,
    run_barrier: Arc<Barrier>,
    pub(crate) run_state: Arc<VcpuRunState>,
}

impl KvmVcpu {
    thread_local!(static TLS_VCPU_PTR: RefCell<Option<*const KvmVcpu>> = RefCell::new(None));

    /// Create a new vCPU.
    pub fn new<M: GuestMemory>(
        vm_fd: &VmFd,
        device_mgr: Arc<Mutex<IoManager>>,
        state: VcpuState,
        run_barrier: Arc<Barrier>,
        run_state: Arc<VcpuRunState>,
        memory: &M,
    ) -> Result<Self> {
        #[cfg(target_arch = "x86_64")]
        let vcpu;
        #[cfg(target_arch = "aarch64")]
        let mut vcpu;

        vcpu = KvmVcpu {
            vcpu_fd: vm_fd
                .create_vcpu(state.id.into())
                .map_err(Error::KvmIoctl)?,
            device_mgr,
            state,
            run_barrier,
            run_state,
        };

        #[cfg(target_arch = "x86_64")]
        {
            vcpu.configure_cpuid(&vcpu.state.cpuid)?;
            vcpu.configure_msrs()?;
            vcpu.configure_sregs(memory)?;
            vcpu.configure_lapic()?;
            vcpu.configure_fpu()?;
        }

        #[cfg(target_arch = "aarch64")]
        {
            vcpu.init(vm_fd)?;
            vcpu.configure_regs(memory)?;
        }

        Ok(vcpu)
    }

    #[cfg(target_arch = "aarch64")]
    fn configure_regs<M: GuestMemory>(&mut self, guest_mem: &M) -> Result<()> {
        // set up registers
        let mut data: u64;
        let mut reg_id: u64;

        // All interrupts masked
        data = (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT | PSR_MODE_EL1h).into();
        reg_id = arm64_core_reg!(pstate);
        self.vcpu_fd
            .set_one_reg(reg_id, data)
            .map_err(Error::SetReg)?;

        // Other cpus are powered off initially
        if self.state.id == 0 {
            /* X0 -- fdt address */
            let mut fdt_offset: u64 = guest_mem.iter().map(|region| region.len()).sum();
            fdt_offset = fdt_offset - AARCH64_FDT_MAX_SIZE - 0x10000;
            data = (AARCH64_PHYS_MEM_START + fdt_offset) as u64;
            // hack -- can't get this to do offsetof(regs[0]) but luckily it's at offset 0
            reg_id = arm64_core_reg!(regs);
            self.vcpu_fd
                .set_one_reg(reg_id, data)
                .map_err(Error::SetReg)?;
        }

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn init(&mut self, vm_fd: &VmFd) -> Result<()> {
        let mut kvi: kvm_vcpu_init = kvm_vcpu_init::default();
        vm_fd
            .get_preferred_target(&mut kvi)
            .map_err(Error::KvmIoctl)?;

        kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_PSCI_0_2;
        // Non-boot cpus are powered off initially.
        if self.state.id > 0 {
            kvi.features[0] |= 1 << kvm_bindings::KVM_ARM_VCPU_POWER_OFF;
        }

        self.vcpu_fd.vcpu_init(&kvi).map_err(Error::KvmIoctl)?;

        Ok(())
    }

    /// Set CPUID.
    #[cfg(target_arch = "x86_64")]
    fn configure_cpuid(&self, cpuid: &CpuId) -> Result<()> {
        self.vcpu_fd.set_cpuid2(cpuid).map_err(Error::KvmIoctl)
    }

    /// Configure MSRs.
    #[cfg(target_arch = "x86_64")]
    fn configure_msrs(&self) -> Result<()> {
        let msrs = msrs::create_boot_msr_entries().map_err(Error::CreateMsr)?;
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
    #[cfg(target_arch = "x86_64")]
    fn configure_regs(&self, instruction_pointer: GuestAddress) -> Result<()> {
        let regs = kvm_regs {
            // EFLAGS (RFLAGS in 64-bit mode) always has bit 1 set.
            // See https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf#page=79
            // Section "EFLAGS Register"
            rflags: 0x0000_0000_0000_0002u64,
            rip: instruction_pointer.raw_value(),
            // Starting stack pointer.
            rsp: BOOT_STACK_POINTER,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rbp: BOOT_STACK_POINTER,
            // Must point to zero page address per Linux ABI. This is x86_64 specific.
            rsi: ZEROPG_START,
            ..Default::default()
        };
        self.vcpu_fd.set_regs(&regs).map_err(Error::KvmIoctl)
    }

    /// Configure sregs.
    #[cfg(target_arch = "x86_64")]
    fn configure_sregs<M: GuestMemory>(&self, guest_memory: &M) -> Result<()> {
        let mut sregs = self.vcpu_fd.get_sregs().map_err(Error::KvmIoctl)?;

        // Global descriptor tables.
        let gdt_table = Gdt::default();

        // The following unwraps are safe because we know that the default GDT has 4 segments.
        let code_seg = gdt_table.create_kvm_segment_for(1).unwrap();
        let data_seg = gdt_table.create_kvm_segment_for(2).unwrap();
        let tss_seg = gdt_table.create_kvm_segment_for(3).unwrap();

        // Write segments to guest memory.
        gdt_table.write_to_mem(guest_memory).map_err(Error::Gdt)?;
        sregs.gdt.base = BOOT_GDT_OFFSET as u64;
        sregs.gdt.limit = std::mem::size_of_val(&gdt_table) as u16 - 1;

        write_idt_value(0, guest_memory).map_err(Error::Gdt)?;
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
    #[cfg(target_arch = "x86_64")]
    fn configure_fpu(&self) -> Result<()> {
        let fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        self.vcpu_fd.set_fpu(&fpu).map_err(Error::KvmIoctl)
    }

    /// Configures LAPICs. LAPIC0 is set for external interrupts, LAPIC1 is set for NMI.
    #[cfg(target_arch = "x86_64")]
    fn configure_lapic(&self) -> Result<()> {
        let mut klapic = self.vcpu_fd.get_lapic().map_err(Error::KvmIoctl)?;

        set_klapic_delivery_mode(&mut klapic, APIC_LVT0, APIC_MODE_EXTINT);
        set_klapic_delivery_mode(&mut klapic, APIC_LVT1, APIC_MODE_NMI);

        self.vcpu_fd.set_lapic(&klapic).map_err(Error::KvmIoctl)
    }

    pub(crate) fn setup_signal_handler() -> Result<()> {
        extern "C" fn handle_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
            KvmVcpu::set_local_immediate_exit(1);
        }
        #[allow(clippy::identity_op)]
        register_signal_handler(SIGRTMIN() + 0, handle_signal)
            .map_err(Error::RegisterSignalHandler)?;
        Ok(())
    }

    fn init_tls(&mut self) -> Result<()> {
        Self::TLS_VCPU_PTR.with(|vcpu| {
            if vcpu.borrow().is_none() {
                *vcpu.borrow_mut() = Some(self as *const KvmVcpu);
                Ok(())
            } else {
                Err(Error::TlsInitialized)
            }
        })?;
        Ok(())
    }

    fn set_local_immediate_exit(value: u8) {
        Self::TLS_VCPU_PTR.with(|v| {
            if let Some(vcpu) = *v.borrow() {
                // The block below modifies a mmaped memory region (`kvm_run` struct) which is valid
                // as long as the `VMM` is still in scope. This function is called in response to
                // SIGRTMIN(), while the vCPU threads are still active. Their termination are
                // strictly bound to the lifespan of the `VMM` and it precedes the `VMM` dropping.
                unsafe {
                    let vcpu_ref = &*vcpu;
                    vcpu_ref.vcpu_fd.set_kvm_immediate_exit(value);
                };
            }
        });
    }

    /// vCPU emulation loop.
    #[allow(clippy::if_same_then_else)]
    pub fn run(&mut self, instruction_pointer: GuestAddress) -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        self.configure_regs(instruction_pointer)?;
        #[cfg(target_arch = "aarch64")]
        if self.state.id == 0 {
            let data = instruction_pointer.0;
            println!("data={}", data);
            let reg_id = arm64_core_reg!(pc);
            self.vcpu_fd
                .set_one_reg(reg_id, data)
                .map_err(Error::SetReg)?;
        }
        self.init_tls()?;

        self.run_barrier.wait();
        'vcpu_run: loop {
            let mut interrupted_by_signal = false;
            match self.vcpu_fd.run() {
                Ok(exit_reason) => {
                    // println!("{:#?}", exit_reason);
                    match exit_reason {
                        VcpuExit::Shutdown | VcpuExit::Hlt => {
                            println!("Guest shutdown: {:?}. Bye!", exit_reason);
                            if stdin().lock().set_canon_mode().is_err() {
                                eprintln!("Failed to set canon mode. Stdin will not echo.");
                            }
                            self.run_state.set_and_notify(VmRunState::Exiting);
                            break;
                        }
                        VcpuExit::IoOut(addr, data) => {
                            if (0x3f8..(0x3f8 + 8)).contains(&addr) {
                                // Write at the serial port.
                                if self
                                    .device_mgr
                                    .lock()
                                    .unwrap()
                                    .pio_write(PioAddress(addr), data)
                                    .is_err()
                                {
                                    debug!("Failed to write to serial port");
                                }
                            } else if addr == 0x060 || addr == 0x061 || addr == 0x064 {
                                // Write at the i8042 port.
                                // See https://wiki.osdev.org/%228042%22_PS/2_Controller#PS.2F2_Controller_IO_Ports
                            } else if (0x070..=0x07f).contains(&addr) {
                                // Write at the RTC port.
                            } else {
                                // Write at some other port.
                            }
                        }
                        VcpuExit::IoIn(addr, data) => {
                            if (0x3f8..(0x3f8 + 8)).contains(&addr) {
                                // Read from the serial port.
                                if self
                                    .device_mgr
                                    .lock()
                                    .unwrap()
                                    .pio_read(PioAddress(addr), data)
                                    .is_err()
                                {
                                    debug!("Failed to read from serial port");
                                }
                            } else {
                                // Read from some other port.
                            }
                        }
                        VcpuExit::MmioRead(addr, data) => {
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_read(MmioAddress(addr), data)
                                .is_err()
                            {
                                debug!("Failed to read from mmio addr={} data={:#?}", addr, data);
                            }
                        }
                        VcpuExit::MmioWrite(addr, data) => {
                            if self
                                .device_mgr
                                .lock()
                                .unwrap()
                                .mmio_write(MmioAddress(addr), data)
                                .is_err()
                            {
                                debug!("Failed to write to mmio");
                            }
                        }
                        #[cfg(target_arch = "aarch64")]
                        VcpuExit::SystemEvent(type_, flags) => match type_ {
                            KVM_SYSTEM_EVENT_SHUTDOWN
                            | KVM_SYSTEM_EVENT_RESET
                            | KVM_SYSTEM_EVENT_CRASH => {
                                println!("Exit reason: {:#?}", VcpuExit::SystemEvent(type_, flags));
                                if stdin().lock().set_canon_mode().is_err() {
                                    eprintln!("Failed to set canon mode. Stdin will not echo.");
                                }
                                self.run_state.set_and_notify(VmRunState::Exiting);
                                break;
                            }
                            _ => {
                                // Unknown system event type
                                debug!("Unknown system event type: {:#?}", type_)
                            }
                        },
                        _other => {
                            // Unhandled KVM exit.
                            debug!("Unhandled vcpu exit: {:#?}", _other);
                        }
                    }
                }
                Err(e) => {
                    // During boot KVM can exit with `EAGAIN`. In that case, do not
                    // terminate the run loop.
                    match e.errno() {
                        libc::EAGAIN => {}
                        libc::EINTR => {
                            interrupted_by_signal = true;
                        }
                        _ => {
                            debug!("Emulation error: {}", e);
                            break;
                        }
                    }
                }
            }

            if interrupted_by_signal {
                self.vcpu_fd.set_kvm_immediate_exit(0);
                let mut run_state_lock = self.run_state.vm_state.lock().unwrap();
                loop {
                    match *run_state_lock {
                        VmRunState::Running => {
                            // The VM state is running, so we need to exit from this loop,
                            // and enter the kvm run loop.
                            break;
                        }
                        VmRunState::Suspending => {
                            // The VM is suspending. We run this loop until we get a different
                            // state.
                        }
                        VmRunState::Exiting => {
                            // The VM is exiting. We also exit from this VCPU thread.
                            break 'vcpu_run;
                        }
                    }
                    // Give ownership of our exclusive lock to the condition variable that will
                    // block. When the condition variable is notified, `wait` will unblock and
                    // return a new exclusive lock.
                    run_state_lock = self.run_state.condvar.wait(run_state_lock).unwrap();
                }
            }
        }

        Ok(())
    }
}

impl Drop for KvmVcpu {
    fn drop(&mut self) {
        Self::TLS_VCPU_PTR.with(|v| {
            *v.borrow_mut() = None;
        });
    }
}
