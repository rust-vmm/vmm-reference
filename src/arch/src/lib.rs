// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use vm_fdt::{Error, FdtWriter, Result};
use vm_memory::{Bytes, GuestAddress, GuestMemory, GuestMemoryRegion};
// This is an arbitrary number to specify the node for the GIC.
// If we had a more complex interrupt architecture, then we'd need an enum for
// these.
const PHANDLE_GIC: u32 = 1;

pub const AARCH64_FDT_MAX_SIZE: u64 = 0x200000;

// This indicates the start of DRAM inside the physical address space.
pub const AARCH64_PHYS_MEM_START: u64 = 0x80000000;

// This is the base address of MMIO devices.
pub const AARCH64_MMIO_BASE: u64 = 1 << 30;

const AARCH64_AXI_BASE: u64 = 0x40000000;

// These constants indicate the address space used by the ARM vGIC.
const AARCH64_GIC_DIST_SIZE: u64 = 0x10000;
const AARCH64_GIC_CPUI_SIZE: u64 = 0x20000;

// This is the minimum number of SPI interrupts aligned to 32 + 32 for the
// PPI (16) and GSI (16).
pub const AARCH64_GIC_NR_IRQS: u32 = 64;

// These constants indicate the placement of the GIC registers in the physical
// address space.
pub const AARCH64_GIC_DIST_BASE: u64 = AARCH64_AXI_BASE - AARCH64_GIC_DIST_SIZE;
pub const AARCH64_GIC_CPUI_BASE: u64 = AARCH64_GIC_DIST_BASE - AARCH64_GIC_CPUI_SIZE;
pub const AARCH64_GIC_REDIST_SIZE: u64 = 0x20000;


// These are specified by the Linux GIC bindings
const GIC_FDT_IRQ_NUM_CELLS: u32 = 3;
const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
const GIC_FDT_IRQ_TYPE_PPI: u32 = 1;
const GIC_FDT_IRQ_PPI_CPU_SHIFT: u32 = 8;
const GIC_FDT_IRQ_PPI_CPU_MASK: u32 = 0xff << GIC_FDT_IRQ_PPI_CPU_SHIFT;
const IRQ_TYPE_EDGE_RISING: u32 = 0x00000001;
const IRQ_TYPE_LEVEL_HIGH: u32 = 0x00000004;
const IRQ_TYPE_LEVEL_LOW: u32 = 0x00000008;
// PMU PPI interrupt, same as qemu
const AARCH64_PMU_IRQ: u32 = 7;
// The RTC device gets the second interrupt line
const AARCH64_RTC_IRQ: u32 = 1;
const AARCH64_RTC_ADDR: u64 = 0x2000;
const AARCH64_RTC_SIZE: u64 = 0x1000;

pub fn create_fdt<T: GuestMemory>(
    cmdline: &str,
    num_vcpus: u32,
    guest_mem: &T,
    fdt_load_offset: u64,
    fdt_max_size: usize,
) -> Result<()> {
    let mut fdt = FdtWriter::new(&[]);

    // The whole thing is put into one giant node with s
    // ome top level properties
    let root_node = fdt.begin_node("")?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", 0x2)?;
    fdt.property_u32("#size-cells", 0x2)?;

    create_chosen_node(&mut fdt, cmdline)?;

    let mem_size: u64 = guest_mem.iter().map(|region| region.len() as u64).sum();
    create_memory_node(&mut fdt, mem_size)?;
    create_cpu_nodes(&mut fdt, num_vcpus)?;
    create_gic_node(&mut fdt, true, num_vcpus as u64)?;
    create_serial_nodes(&mut fdt);
    create_rtc_node(&mut fdt);
    create_timer_node(&mut fdt, num_vcpus);
    create_psci_node(&mut fdt);
    create_pmu_node(&mut fdt, num_vcpus);

    fdt.end_node(root_node)?;
    let fdt_final = fdt.finish(fdt_max_size)?;

    let fdt_address = GuestAddress(AARCH64_PHYS_MEM_START + fdt_load_offset);
    guest_mem
        .write_slice(fdt_final.as_slice(), fdt_address)
        .map_err(|_| Error::FdtGuestMemoryWriteError)?;

    Ok(())
}

fn create_chosen_node(fdt: &mut FdtWriter, cmdline: &str) -> Result<()> {
    let chosen_node = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", cmdline)?;
    fdt.end_node(chosen_node)?;

    Ok(())
}

fn create_memory_node(fdt: &mut FdtWriter, mem_size: u64) -> Result<()> {
    let mem_reg_prop = [AARCH64_PHYS_MEM_START, mem_size];

    let memory_node = fdt.begin_node("memory")?;
    fdt.property_string("device_type", "memory")?;
    fdt.property_array_u64("reg", &mem_reg_prop)?;
    fdt.end_node(memory_node)?;
    Ok(())
}

fn create_cpu_nodes(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    let cpus_node = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 0x1)?;
    fdt.property_u32("#size-cells", 0x0)?;

    for cpu_id in 0..num_cpus {
        let cpu_name = format!("cpu@{:x}", cpu_id);
        let cpu_node = fdt.begin_node(&cpu_name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        if num_cpus > 1 {
            fdt.property_string("enable-method", "psci")?;
        }
        fdt.property_u32("reg", cpu_id)?;
        fdt.end_node(cpu_node)?;
    }
    fdt.end_node(cpus_node)?;
    Ok(())
}

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
    fdt.property_u32("phandle", PHANDLE_GIC)?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;
    fdt.end_node(intc_node)?;

    Ok(())
}

fn create_psci_node(fdt: &mut FdtWriter) -> Result<()> {
    let compatible = "arm,psci-0.2";
    let psci_node = fdt.begin_node("psci")?;
    fdt.property_string("compatible", compatible);
    // Two methods available: hvc and smc.
    // As per documentation, PSCI calls between a guest and hypervisor may use the HVC conduit instead of SMC.
    // So, since we are using kvm, we need to use hvc.
    fdt.property_string( "method", "hvc")?;
    fdt.end_node(psci_node)?;

    Ok(())
}

fn create_serial_nodes(fdt: &mut FdtWriter) -> Result<()> {
    // const SERIAL_ADDR: [u64; 4] = [0x3f8, 0x2f8, 0x3e8, 0x2e8];
    // // The serial device gets the first interrupt line
    // // Which gets mapped to the first SPI interrupt (physical 32).
    // const AARCH64_SERIAL_1_3_IRQ: u32 = 0;
    // const AARCH64_SERIAL_2_4_IRQ: u32 = 2;
    // // Note that SERIAL_ADDR contains the I/O port addresses conventionally used
    // // for serial ports on x86. This uses the same addresses (but on the MMIO bus)
    // // to simplify the shared serial code.
    // create_serial_node(fdt, SERIAL_ADDR[0], AARCH64_SERIAL_1_3_IRQ)?;
    // create_serial_node(fdt, SERIAL_ADDR[1], AARCH64_SERIAL_2_4_IRQ)?;
    // create_serial_node(fdt, SERIAL_ADDR[2], AARCH64_SERIAL_1_3_IRQ)?;
    // create_serial_node(fdt, SERIAL_ADDR[3], AARCH64_SERIAL_2_4_IRQ)?;
    let addr =  0x40000000;
    const AARCH64_SERIAL_SPEED: u32 = 1843200;
    let serial_node = fdt.begin_node(&format!("uart@{:x}", addr))?;
    fdt.property_string("compatible", "ns16550a")?;
    let serial_reg_prop = [addr, 0x1000];
    fdt.property_array_u64("reg", &serial_reg_prop)?;

    // fdt.property_u32("clock-frequency", AARCH64_SERIAL_SPEED)?;
    const CLK_PHANDLE: u32 = 24;
    fdt.property_u32("clocks", CLK_PHANDLE);
    fdt.property_string("clock-names", "apb_pclk");
    let irq = [GIC_FDT_IRQ_TYPE_SPI, 4, IRQ_TYPE_EDGE_RISING];
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;
    Ok(())
}

fn create_serial_node(fdt: &mut FdtWriter, addr: u64, irq: u32) -> Result<()> {
    // Serial device requires 8 bytes of registers;
    const AARCH64_SERIAL_SIZE: u64 = 0x8;
    const GIC_FDT_IRQ_TYPE_SPI: u32 = 0;
    // This was the speed kvmtool used, not sure if it matters.
    const AARCH64_SERIAL_SPEED: u32 = 1843200;

    let serial_reg_prop = [addr, AARCH64_SERIAL_SIZE];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, irq, IRQ_TYPE_EDGE_RISING];

    let serial_node = fdt.begin_node(&format!("U6_16550A@{:x}", addr))?;
    fdt.property_string("compatible", "ns16550a")?;
    fdt.property_array_u64("reg", &serial_reg_prop)?;
    fdt.property_u32("clock-frequency", AARCH64_SERIAL_SPEED)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.end_node(serial_node)?;

    Ok(())
}

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

fn create_rtc_node(fdt: &mut FdtWriter) -> Result<()> {
    // the kernel driver for pl030 really really wants a clock node
    // associated with an AMBA device or it will fail to probe, so we
    // need to make up a clock node to associate with the pl030 rtc
    // node and an associated handle with a unique phandle value.
    const CLK_PHANDLE: u32 = 24;
    let clock_node = fdt.begin_node("apb-pclk")?;
    fdt.property_u32("#clock-cells", 0)?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("clock-frequency", 24_000_000)?;
    fdt.property_string("clock-output-names", "clk24mhz");
    fdt.property_u32("phandle", CLK_PHANDLE)?;
    fdt.end_node(clock_node)?;

    let rtc_addr = 0x40001000;
    let rtc_name = format!("rtc@{:x}", rtc_addr);
    let reg = [rtc_addr, 0x1000];
    let irq = [GIC_FDT_IRQ_TYPE_SPI, 33, IRQ_TYPE_LEVEL_HIGH];

    let rtc_node = fdt.begin_node(&rtc_name)?;
    fdt.property_string_list("compatible", vec![String::from("arm,pl031"), String::from("arm,primecell")])?;
    // const PL030_AMBA_ID: u32 = 0x00041030;
    // fdt.property_string("arm,pl031", PL030_AMBA_ID)?;
    fdt.property_array_u64("reg", &reg)?;
    fdt.property_array_u32("interrupts", &irq)?;
    fdt.property_u32("clocks", CLK_PHANDLE)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc_node)?;
    Ok(())
}
