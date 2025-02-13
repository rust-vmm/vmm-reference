// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is an arbitrary number to specify the node for the GIC.
// If we had a more complex interrupt architecture, then we'd need an enum for
// these.
#[cfg(target_arch = "aarch64")]
pub mod aarch64_consts {
    // These constants indicate the placement of the GIC registers in the physical
    // address space.
    pub const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;

    pub const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;

    pub const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;

    pub const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;

    // This indicates the start of DRAM inside the physical address space.
    pub const AARCH64_PHYS_MEM_START: u64 = 0x80000000;

    // This is the base address of MMIO devices.
    pub const AARCH64_MMIO_BASE: u64 = 1 << 30;

    pub const AARCH64_AXI_BASE: u64 = 0x40000000;

    // These constants indicate the address space used by the ARM vGIC.
    pub const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;

    pub const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

    // These are specified by the Linux GIC bindings
    pub const GIC_FDT_IRQ_NUM_CELLS: u32 = 3;

    pub const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;

    pub const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;

    pub const GIC_FDT_IRQ_PPI_CPU_SHIFT: u32 = 8;

    pub const GIC_FDT_IRQ_PPI_CPU_MASK: u32 = 0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT;

    // PMU PPI interrupt, same as qemu
    pub const AARCH64_PMU_IRQ: u32 = 7;

    pub const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;

    pub const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;

    pub const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;

    pub const PHANDLE_GIC: u32 = 1;
}

// RISCV
#[cfg(target_arch = "riscv64")]
pub mod riscv64_consts {
    pub const RISCV_PLIC: u64 = 0x0c00_0000;

    pub const RISCV_PLIC_SIZE: u64 = 0x600_000;

    pub const RISCV_IMSIC: u64 = 0x28000000;

    pub const RISCV_IMSIC_SIZE: u64 = 0x1000;

    pub const PHANDLE_CPU_INTC_BASE: u32 = 1;

    pub const PHANDLE_APLIC: u32 = 0xd;

    pub const PHANDLE_IMSIC: u32 = 0x9;

    pub const MAX_DEVICES: u32 = 1024;

    // This indicates the start of DRAM inside the physical address space.
    pub const RISCV64_PHYS_MEM_START: u64 = 0x80000000;

    pub const RISCV64_FDT_MAX_SIZE: u64 = 0x200000;

    pub const RISCV64_MMIO_BASE: u64 = 1 << 30;

    pub const FDT_APLIC_INT_CELLS: u32 = 2;

    pub const FDT_APLIC_ADDR_CELLS: u32 = 0;

    pub const VIRT_IRQCHIP_NUM_SOURCES: u32 = 96;

    pub const IRQ_S_EXT: u32 = 0x9;

    pub const VIRT_IRQCHIP_NUM_MSIS: u32 = 255;

    pub const FDT_IMSIC_INT_CELLS: u32 = 0;

    pub const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;

    pub const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;

    pub const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;
}

#[cfg(target_arch = "riscv64")]
mod riscv_regs;

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub mod fdt {
    #[cfg(target_arch = "riscv64")]
    use kvm_bindings::*;
    #[cfg(target_arch = "riscv64")]
    use kvm_ioctls::VcpuFd;
    use log::debug;
    #[cfg(target_arch = "riscv64")]
    use std::mem::offset_of;
    use std::path::PathBuf;
    use std::{
        fs::File,
        io::{self, Read, Write},
    };
    pub use vm_fdt::{Error as FdtError, FdtWriter};
    use vm_memory::{guest_memory::Error as GuestMemoryError, Bytes, GuestAddress, GuestMemory};

    #[cfg(target_arch = "aarch64")]
    use crate::aarch64_consts::*;

    #[cfg(target_arch = "riscv64")]
    use crate::riscv64_consts::*;
    #[cfg(target_arch = "riscv64")]
    use crate::*;
    #[cfg(target_arch = "riscv64")]
    const ISA_INFO_ARR: [(&str, u32); 9] = [
        /* sorted alphabetically */
        ("ssaia", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSAIA),
        ("sstc", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SSTC),
        ("svinval", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVINVAL),
        ("svnapot", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVNAPOT),
        ("svpbmt", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_SVPBMT),
        ("zbb", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZBB),
        ("zicbom", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOM),
        ("zicboz", KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOZ),
        (
            "zihintpause",
            KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZIHINTPAUSE,
        ),
    ];
    #[derive(Debug)]
    pub enum Error {
        Fdt(FdtError),
        Memory(GuestMemoryError),
        MissingRequiredConfig(String),
        FdtCustomDtb(io::Error),
    }

    impl From<FdtError> for Error {
        fn from(inner: FdtError) -> Self {
            Error::Fdt(inner)
        }
    }

    impl From<GuestMemoryError> for Error {
        fn from(inner: GuestMemoryError) -> Self {
            Error::Memory(inner)
        }
    }

    impl From<io::Error> for Error {
        fn from(inner: io::Error) -> Self {
            Error::FdtCustomDtb(inner)
        }
    }

    pub type Result<T> = std::result::Result<T, Error>;

    /// It contains info about the virtio device for fdt.
    struct DeviceInfo {
        addr: u64,
        size: u64,
        irq: u32,
    }

    #[derive(Default)]
    pub struct FdtBuilder {
        cmdline: Option<String>,
        mem_size: Option<u64>,
        num_vcpus: Option<u32>,
        serial_console: Option<(u64, u64)>,
        rtc: Option<(u64, u64)>,
        virtio_devices: Vec<DeviceInfo>,
        prebuilt: Option<Fdt>,
    }

    impl FdtBuilder {
        pub fn new() -> Self {
            FdtBuilder::default()
        }

        pub fn with_prebuilt_fdt(&mut self, prebuilt_fdt_path: PathBuf) -> Result<&mut Self> {
            let mut fdt_file = File::options()
                .read(true)
                .create(false)
                .write(false)
                .append(false)
                .open(prebuilt_fdt_path)
                .map_err(Error::FdtCustomDtb)?;

            let mut prebuilt_fdt = Fdt::default();
            fdt_file
                .read_to_end(&mut prebuilt_fdt.fdt_blob)
                .map_err(Error::FdtCustomDtb)?;
            self.prebuilt = Some(prebuilt_fdt);
            Ok(self)
        }

        pub fn has_prebuilt_fdt(&self) -> bool {
            self.prebuilt.is_some()
        }

        pub fn get_prebuilt_fdt(&self) -> Option<Fdt> {
            self.prebuilt.clone()
        }

        pub fn with_cmdline(&mut self, cmdline: String) -> &mut Self {
            self.cmdline = Some(cmdline);
            self
        }

        pub fn with_mem_size(&mut self, mem_size: u64) -> &mut Self {
            self.mem_size = Some(mem_size);
            self
        }

        pub fn with_num_vcpus(&mut self, num_vcpus: u32) -> &mut Self {
            self.num_vcpus = Some(num_vcpus);
            self
        }

        pub fn with_serial_console(&mut self, addr: u64, size: u64) -> &mut Self {
            self.serial_console = Some((addr, size));
            self
        }

        pub fn with_rtc(&mut self, addr: u64, size: u64) -> &mut Self {
            self.rtc = Some((addr, size));
            self
        }

        pub fn add_virtio_device(&mut self, addr: u64, size: u64, irq: u32) -> &mut Self {
            self.virtio_devices.push(DeviceInfo { addr, size, irq });
            self
        }

        pub fn virtio_device_len(&self) -> usize {
            self.virtio_devices.len()
        }

        #[allow(clippy::needless_borrow)]
        pub fn create_fdt(
            &mut self,
            #[cfg(target_arch = "riscv64")] vcpufd: &VcpuFd,
        ) -> Result<Fdt> {
            if let Some(fdt) = &mut self.prebuilt {
                let ret: Fdt = fdt.clone();
                fdt.fdt_blob.clear();
                debug!("FdtBuilder: Returning prebuilt FDT");
                return Ok(ret);
            }

            let mut fdt = FdtWriter::new()?;

            // The whole thing is put into one giant node with s
            // ome top level properties
            let root_node = fdt.begin_node("")?;
            #[cfg(target_arch = "aarch64")]
            fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
            fdt.property_u32("#address-cells", 0x2)?;
            fdt.property_u32("#size-cells", 0x2)?;
            fdt.property_string("compatible", "riscv-virtio")?;
            fdt.property_string("model", "linux,dummy-virt")?;

            let cmdline = self
                .cmdline
                .as_ref()
                .ok_or_else(|| Error::MissingRequiredConfig("cmdline".to_owned()))?;
            create_chosen_node(&mut fdt, cmdline)?;

            let mem_size = self
                .mem_size
                .ok_or_else(|| Error::MissingRequiredConfig("memory".to_owned()))?;
            create_memory_node(&mut fdt, mem_size)?;

            let num_vcpus = self
                .num_vcpus
                .ok_or_else(|| Error::MissingRequiredConfig("vcpu".to_owned()))?;

            #[cfg(target_arch = "aarch64")]
            {
                create_cpu_nodes(&mut fdt, num_vcpus)?;
                create_gic_node(&mut fdt, true, num_vcpus as u64)?;
            }
            #[cfg(target_arch = "riscv64")]
            {
                create_cpu_nodes(&mut fdt, num_vcpus, &vcpufd)?;
                create_aplic_node(&mut fdt)?;
                create_imsic_node(&mut fdt, num_vcpus)?;
            }

            if let Some(serial_console) = self.serial_console {
                create_serial_node(&mut fdt, serial_console.0, serial_console.1)?;
            }
            if let Some(rtc) = self.rtc {
                create_rtc_node(&mut fdt, rtc.0, rtc.1)?;
            }

            #[cfg(target_arch = "aarch64")]
            {
                create_timer_node(&mut fdt, num_vcpus)?;
                create_psci_node(&mut fdt)?;
                create_pmu_node(&mut fdt, num_vcpus)?;
            }

            for info in &self.virtio_devices {
                create_virtio_node(&mut fdt, info.addr, info.size, info.irq)?;
            }

            fdt.end_node(root_node)?;

            Ok(Fdt {
                fdt_blob: fdt.finish()?,
            })
        }
    }

    #[derive(Default, Clone)]
    pub struct Fdt {
        fdt_blob: Vec<u8>,
    }

    impl Fdt {
        pub fn write_to_mem<T: GuestMemory>(
            &self,
            guest_mem: &T,
            fdt_load_offset: u64,
        ) -> Result<()> {
            #[cfg(target_arch = "aarch64")]
            let fdt_address = GuestAddress(AARCH64_PHYS_MEM_START + fdt_load_offset);
            #[cfg(target_arch = "riscv64")]
            let fdt_address = GuestAddress(RISCV64_PHYS_MEM_START + fdt_load_offset);
            guest_mem.write_slice(self.fdt_blob.as_slice(), fdt_address)?;
            Ok(())
        }

        pub fn write_to_file(&self, path: &str) -> std::io::Result<()> {
            let mut file = File::options()
                .read(false)
                .create(true)
                .truncate(true)
                .write(true)
                .append(false)
                .open(path)?;
            file.write_all(&self.fdt_blob)?;
            Ok(())
        }
    }

    fn create_chosen_node(fdt: &mut FdtWriter, cmdline: &str) -> Result<()> {
        let chosen_node = fdt.begin_node("chosen")?;
        fdt.property_string("bootargs", cmdline)?;
        fdt.end_node(chosen_node)?;

        Ok(())
    }

    fn create_memory_node(fdt: &mut FdtWriter, mem_size: u64) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let mem_reg_prop = [AARCH64_PHYS_MEM_START, mem_size];
            let memory_str = format!("memory@{:x}", AARCH64_PHYS_MEM_START);
            let memory_node = fdt.begin_node(&memory_str)?;
            fdt.property_string("device_type", "memory")?;
            fdt.property_array_u64("reg", &mem_reg_prop)?;
            fdt.end_node(memory_node)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let mem_reg_prop = [RISCV64_PHYS_MEM_START, mem_size];
            let memory_str = format!("memory@{:x}", RISCV64_PHYS_MEM_START);
            let memory_node = fdt.begin_node(&memory_str)?;
            fdt.property_string("device_type", "memory")?;
            fdt.property_array_u64("reg", &mem_reg_prop)?;
            fdt.end_node(memory_node)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
        let cpus_node = fdt.begin_node("cpus")?;
        fdt.property_u32("#address-cells", 0x1)?;
        fdt.property_u32("#size-cells", 0x0)?;

        for cpu_id in 0..num_cpus {
            let cpu_name = format!("cpu@{:x}", cpu_id);
            let cpu_node = fdt.begin_node(&cpu_name)?;
            fdt.property_string("device_type", "cpu")?;
            fdt.property_u32("reg", cpu_id)?;
            fdt.property_string("compatible", "arm,arm-v8")?;
            fdt.property_string("enable-method", "psci")?;
            fdt.end_node(cpu_node)?;
        }
        fdt.end_node(cpus_node)?;
        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32, vcpu_fd: &VcpuFd) -> Result<()> {
        let isa_id: u64 = riscv_config_reg!(isa);
        let mut data = [0_u8; 8];
        vcpu_fd.get_one_reg(isa_id, &mut data).expect("Error");
        let isa = u64::from_le_bytes(data);
        let valid_isa_order = "IEMAFDQCLBJTPVNSUHKORWXYZG";
        let arr_sz = ISA_INFO_ARR.len();
        let cpus_node = fdt.begin_node("cpus")?;
        fdt.property_u32("#address-cells", 0x1)?;
        fdt.property_u32("#size-cells", 0x0)?;
        let timer_id: u64 = riscv_timer_reg!(frequency);
        let mut data = [0_u8; 8];
        vcpu_fd.get_one_reg(timer_id, &mut data).expect("Error");
        let frequency = u64::from_le_bytes(data);
        fdt.property_u32("timebase-frequency", frequency as u32)?;

        for cpu_id in 0..num_cpus {
            let mut cpu_isa = String::from("rv64");
            let mut cbom_blksz = 0;
            let mut cboz_blksz = 0;
            for c in valid_isa_order.chars() {
                let index = c as u32 - 'A' as u32;
                if (isa & (1 << index)) != 0 {
                    let ret = 'a' as u32 + index;
                    cpu_isa += &std::char::from_u32(ret).unwrap().to_string();
                }
            }

            for info in ISA_INFO_ARR.iter().take(arr_sz) {
                let reg_id = riscv_isa_ext_reg!(info.1 as u64);
                let mut data = [0_u8; 8];
                if vcpu_fd.get_one_reg(reg_id, &mut data).is_err() {
                    continue;
                }
                let isa_ext_out = u64::from_le_bytes(data);
                if isa_ext_out == 0 {
                    continue;
                }

                if info.1 == KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOM && cbom_blksz == 0 {
                    vcpu_fd.get_one_reg(reg_id, &mut data).expect("Error");
                    cbom_blksz = u64::from_le_bytes(data);
                }

                if info.1 == KVM_RISCV_ISA_EXT_ID_KVM_RISCV_ISA_EXT_ZICBOZ && cboz_blksz == 0 {
                    vcpu_fd.get_one_reg(reg_id, &mut data).expect("Error");
                    cboz_blksz = u64::from_le_bytes(data);
                }
                cpu_isa += "_";
                cpu_isa += info.0;
            }

            let reg_id = riscv_config_reg!(satp_mode);
            let mut data = [0_u8; 8];
            vcpu_fd.get_one_reg(reg_id, &mut data).expect("Error");
            let satp_mode = u64::from_le_bytes(data);

            let cpu_name = format!("cpu@{:x}", cpu_id);
            let cpu_node = fdt.begin_node(&cpu_name)?;
            fdt.property_string("device_type", "cpu")?;
            fdt.property_string("compatible", "riscv")?;
            match satp_mode {
                10 => fdt.property_string("mmu-type", "riscv,sv57")?,
                9 => fdt.property_string("mmu-type", "riscv,sv48")?,
                8 => fdt.property_string("mmu-type", "riscv,sv39")?,
                _ => fdt.property_string("mmu-type", "riscv,none")?,
            }
            fdt.property_string("riscv,isa", &cpu_isa)?;
            if cbom_blksz != 0 {
                fdt.property_u32("riscv,cbom-block-size", cbom_blksz as u32)?;
            }

            if cbom_blksz != 0 {
                fdt.property_u32("riscv,cboz-block-size", cboz_blksz as u32)?;
            }

            fdt.property_u32("reg", cpu_id)?;
            fdt.property_string("status", "okay")?;
            let intc_node = fdt.begin_node("interrupt-controller")?;
            fdt.property_u32("#interrupt-cells", 1)?;
            fdt.property_string("compatible", "riscv,cpu-intc")?;
            fdt.property_null("interrupt-controller")?;
            fdt.property_phandle(PHANDLE_CPU_INTC_BASE + cpu_id)?;
            fdt.end_node(intc_node)?;
            fdt.end_node(cpu_node)?;
        }
        fdt.end_node(cpus_node)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_gic_node(fdt: &mut FdtWriter, is_gicv3: bool, num_cpus: u64) -> Result<()> {
        let mut gic_reg_prop = [AARCH64_GIC_DIST_BASE, AARCH64_GIC_DIST_SIZE, 0, 0];

        let intc_node = fdt.begin_node("intc")?;
        if is_gicv3 {
            fdt.property_string("compatible", "arm,gic-v3")?;
            gic_reg_prop[2] = AARCH64_GIC_DIST_BASE - (AARCH64_GIC_REDIST_SIZE * num_cpus);
            gic_reg_prop[3] = AARCH64_GIC_REDIST_SIZE * num_cpus;
        } else {
            fdt.property_string("compatible", "arm,cortex-a15-gic")?;
            gic_reg_prop[2] = AARCH64_GIC_CPUI_BASE;
            gic_reg_prop[3] = AARCH64_GIC_CPUI_SIZE;
        }
        fdt.property_u32("#interrupt-cells", GIC_FDT_IRQ_NUM_CELLS)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_array_u64("reg", &gic_reg_prop)?;
        fdt.property_phandle(PHANDLE_GIC)?;
        fdt.property_u32("#address-cells", 2)?;
        fdt.property_u32("#size-cells", 2)?;
        fdt.end_node(intc_node)?;

        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    fn create_aplic_node(fdt: &mut FdtWriter) -> Result<()> {
        let intc_node = fdt.begin_node(&format!("aplic@{:x}", RISCV_PLIC))?;
        fdt.property_phandle(PHANDLE_APLIC)?;
        fdt.property_u32("riscv,num-sources", VIRT_IRQCHIP_NUM_SOURCES)?;
        fdt.property_u32("msi-parent", PHANDLE_IMSIC)?;
        fdt.property_u32("riscv,ndev", MAX_DEVICES - 1)?;
        let plic_reg_prop = [RISCV_PLIC, RISCV_PLIC_SIZE];
        fdt.property_array_u64("reg", &plic_reg_prop)?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,aplic")?;
        fdt.property_u32("#address-cells", FDT_APLIC_ADDR_CELLS)?;
        fdt.property_u32("#interrupt-cells", FDT_APLIC_INT_CELLS)?;
        fdt.end_node(intc_node)?;

        Ok(())
    }

    #[cfg(target_arch = "riscv64")]
    fn create_imsic_node(fdt: &mut FdtWriter, num_vcpus: u32) -> Result<()> {
        let imsic_cells: Vec<_> = (0..num_vcpus)
            .flat_map(|cpu| vec![PHANDLE_CPU_INTC_BASE + cpu, IRQ_S_EXT])
            .collect();

        let imsic_regs = [RISCV_IMSIC, 0x8000];

        let intc_node = fdt.begin_node(&format!("imsic@{:x}", RISCV_IMSIC))?;
        fdt.property_array_u64("reg", &imsic_regs)?;
        fdt.property_array_u32("interrupts-extended", &imsic_cells)?;
        fdt.property_u32("#interrupt-cells", FDT_IMSIC_INT_CELLS)?;
        fdt.property_null("msi-controller")?;
        fdt.property_null("interrupt-controller")?;
        fdt.property_string("compatible", "riscv,imsics")?;
        fdt.property_phandle(PHANDLE_IMSIC)?;
        fdt.property_u32("riscv,num-ids", VIRT_IRQCHIP_NUM_MSIS)?;
        fdt.end_node(intc_node)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_psci_node(fdt: &mut FdtWriter) -> Result<()> {
        let compatible = "arm,psci-0.2";
        let psci_node = fdt.begin_node("psci")?;
        fdt.property_string("compatible", compatible)?;
        // Two methods available: hvc and smc.
        // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
        // So, since we are using kvm, we need to use hvc.
        fdt.property_string("method", "hvc")?;
        fdt.end_node(psci_node)?;

        Ok(())
    }

    fn create_serial_node(fdt: &mut FdtWriter, addr: u64, size: u64) -> Result<()> {
        #[cfg(target_arch = "aarch64")]
        {
            let serial_node = fdt.begin_node(&format!("uart@{:x}", addr))?;
            fdt.property_string("compatible", "ns16550a")?;
            let serial_reg_prop = [addr, size];
            fdt.property_array_u64("reg", &serial_reg_prop)?;

            const CLK_PHANDLE: u32 = 24;
            fdt.property_u32("clocks", CLK_PHANDLE)?;
            fdt.property_string("clock-names", "apb_pclk")?;
            let irq = [GIC_FDT_IRQ_TYPE_SPI, 4, IRQ_TYPE_EDGE_RISING];
            fdt.property_array_u32("interrupts", &irq)?;
            fdt.end_node(serial_node)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            let serial_node = fdt.begin_node(&format!("serial@{:x}", addr))?;
            fdt.property_array_u32("interrupts", &[4, IRQ_TYPE_LEVEL_HIGH])?;
            fdt.property_u32("interrupt-parent", PHANDLE_APLIC)?;
            let strs = vec!["".into(), "8@".into()];

            fdt.property_string_list("clock-frequency", strs)?;
            let serial_reg_prop = [addr, size];
            fdt.property_array_u64("reg", &serial_reg_prop)?;
            fdt.property_string("compatible", "ns16550a")?;
            fdt.end_node(serial_node)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_timer_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
        // These are fixed interrupt numbers for the timer device.
        let irqs = [13, 14, 11, 10];
        let compatible = "arm,armv8-timer";
        let cpu_mask: u32 =
            (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;

        let mut timer_reg_cells = Vec::new();
        for &irq in &irqs {
            timer_reg_cells.push(GIC_FDT_IRQ_TYPE_PPI);
            timer_reg_cells.push(irq);
            timer_reg_cells.push(cpu_mask | IRQ_TYPE_LEVEL_LOW);
        }

        let timer_node = fdt.begin_node("timer")?;
        fdt.property_string("compatible", compatible)?;
        fdt.property_array_u32("interrupts", &timer_reg_cells)?;
        fdt.property_null("always-on")?;
        fdt.end_node(timer_node)?;

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn create_pmu_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
        let compatible = "arm,armv8-pmuv3";
        let cpu_mask: u32 =
            (((1 << num_cpus) - 1) << GIC_FDT_IRQ_PPI_CPU_SHIFT) & GIC_FDT_IRQ_PPI_CPU_MASK;
        let irq = [
            GIC_FDT_IRQ_TYPE_PPI,
            AARCH64_PMU_IRQ,
            cpu_mask | IRQ_TYPE_LEVEL_HIGH,
        ];

        let pmu_node = fdt.begin_node("pmu")?;
        fdt.property_string("compatible", compatible)?;
        fdt.property_array_u32("interrupts", &irq)?;
        fdt.end_node(pmu_node)?;
        Ok(())
    }

    fn create_rtc_node(fdt: &mut FdtWriter, rtc_addr: u64, size: u64) -> Result<()> {
        // the kernel driver for pl030 really really wants a clock node
        // associated with an AMBA device or it will fail to probe, so we
        // need to make up a clock node to associate with the pl030 rtc
        // node and an associated handle with a unique phandle value.
        #[cfg(target_arch = "aarch64")]
        {
            const CLK_PHANDLE: u32 = 24;
            let clock_node = fdt.begin_node("apb-pclk")?;
            fdt.property_u32("#clock-cells", 0)?;
            fdt.property_string("compatible", "fixed-clock")?;
            fdt.property_u32("clock-frequency", 24_000_000)?;
            fdt.property_string("clock-output-names", "clk24mhz")?;
            fdt.property_phandle(CLK_PHANDLE)?;
            fdt.end_node(clock_node)?;

            let rtc_name = format!("rtc@{:x}", rtc_addr);
            let reg = [rtc_addr, size];
            let irq = [GIC_FDT_IRQ_TYPE_SPI, 33, IRQ_TYPE_LEVEL_HIGH];

            let rtc_node = fdt.begin_node(&rtc_name)?;
            fdt.property_string_list(
                "compatible",
                vec![String::from("arm,pl031"), String::from("arm,primecell")],
            )?;
            // const PL030_AMBA_ID: u32 = 0x00041030;
            // fdt.property_string("arm,pl031", PL030_AMBA_ID)?;
            fdt.property_array_u64("reg", &reg)?;
            fdt.property_array_u32("interrupts", &irq)?;
            fdt.property_u32("clocks", CLK_PHANDLE)?;
            fdt.property_string("clock-names", "apb_pclk")?;
            fdt.end_node(rtc_node)?;
        }
        #[cfg(target_arch = "riscv64")]
        {
            const CLK_PHANDLE: u32 = 24;
            let clock_node = fdt.begin_node("apb-pclk")?;
            fdt.property_u32("#clock-cells", 0)?;
            fdt.property_string("compatible", "fixed-clock")?;
            fdt.property_u32("clock-frequency", 24_000_000)?;
            fdt.property_string("clock-output-names", "clk24mhz")?;
            fdt.property_phandle(CLK_PHANDLE)?;
            fdt.end_node(clock_node)?;

            let rtc_name = format!("rtc@{:x}", rtc_addr);
            let reg = [rtc_addr, size];

            let rtc_node = fdt.begin_node(&rtc_name)?;
            fdt.property_string("compatible", "apb_pclk")?;
            fdt.property_array_u64("reg", &reg)?;
            fdt.property_array_u32("interrupts", &[PHANDLE_CPU_INTC_BASE, IRQ_TYPE_LEVEL_HIGH])?;
            fdt.property_u32("interrupt-parent", PHANDLE_APLIC)?;
            fdt.property_u32("clocks", CLK_PHANDLE)?;
            fdt.end_node(rtc_node)?;
        }
        Ok(())
    }

    fn create_virtio_node(fdt: &mut FdtWriter, addr: u64, size: u64, irq: u32) -> Result<()> {
        let virtio_mmio = fdt.begin_node(&format!("virtio_mmio@{:x}", addr))?;
        fdt.property_string("compatible", "virtio,mmio")?;
        fdt.property_array_u64("reg", &[addr, size])?;
        #[cfg(target_arch = "aarch64")]
        {
            fdt.property_array_u32(
                "interrupts",
                &[GIC_FDT_IRQ_TYPE_SPI, irq, IRQ_TYPE_EDGE_RISING],
            )?;
            fdt.property_array_u32("interrupt-parent", &[PHANDLE_GIC])?;
        }

        #[cfg(target_arch = "riscv64")]
        {
            fdt.property_array_u32("interrupts", &[irq, IRQ_TYPE_LEVEL_HIGH])?;
            fdt.property_array_u32("interrupt-parent", &[PHANDLE_APLIC])?;
        }

        fdt.end_node(virtio_mmio)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use crate::fdt::FdtBuilder;
        #[cfg(target_arch = "riscv64")]
        use kvm_ioctls::Kvm;

        #[test]
        #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
        fn test_adding_virtio() {
            let mut fdt = FdtBuilder::new();
            let fdt = fdt.add_virtio_device(0x1000, 1000, 5);
            assert_eq!(fdt.virtio_devices.len(), 1);
            assert_eq!(fdt.virtio_device_len(), 1);
        }

        #[test]
        #[cfg(target_arch = "aarch64")]
        fn test_create_fdt() {
            let fdt_ok = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_num_vcpus(8)
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .add_virtio_device(0x1000, 1000, 5)
                .create_fdt();
            assert!(fdt_ok.is_ok());

            let fdt_no_cmdline = FdtBuilder::new()
                .with_num_vcpus(8)
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt();
            assert!(fdt_no_cmdline.is_err());

            let fdt_no_num_vcpus = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt();
            assert!(fdt_no_num_vcpus.is_err());

            let fdt_no_mem_size = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_num_vcpus(8)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt();
            assert!(fdt_no_mem_size.is_err());
        }

        #[test]
        #[cfg(target_arch = "riscv64")]
        fn test_create_fdt() {
            let kvm = Kvm::new().unwrap();
            let vm = kvm.create_vm().unwrap();
            let vcpu = vm.create_vcpu(0).unwrap();

            let fdt_ok = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_num_vcpus(8)
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .add_virtio_device(0x1000, 1000, 5)
                .create_fdt(&vcpu);
            assert!(fdt_ok.is_ok());

            let fdt_no_cmdline = FdtBuilder::new()
                .with_num_vcpus(8)
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt(&vcpu);
            assert!(fdt_no_cmdline.is_err());

            let fdt_no_num_vcpus = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_mem_size(4096)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt(&vcpu);
            assert!(fdt_no_num_vcpus.is_err());

            let fdt_no_mem_size = FdtBuilder::new()
                .with_cmdline(String::from("reboot=t panic=1 pci=off"))
                .with_num_vcpus(8)
                .with_serial_console(0x40000000, 0x1000)
                .with_rtc(0x40001000, 0x1000)
                .create_fdt(&vcpu);
            assert!(fdt_no_mem_size.is_err());
        }
    }
}
