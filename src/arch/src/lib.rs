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

pub fn create_fdt<T: GuestMemory>(
    cmdline: &str,
    guest_mem: &T,
    fdt_load_offset: u64,
    fdt_max_size: usize,
) -> Result<()> {
    let mut fdt = FdtWriter::new(&[]);

    // The whole thing is put into one giant node with some top level properties
    let root_node = fdt.begin_node("")?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", 0x2)?;
    fdt.property_u32("#size-cells", 0x2)?;

    create_chosen_node(&mut fdt, cmdline)?;

    let mem_size: u64 = guest_mem.iter().map(|region| region.len() as u64).sum();
    create_memory_node(&mut fdt, mem_size);

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
