// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

use std::result;

use linux_loader::bootparam::boot_params;
use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryMmap};

// x86_64 boot constants. See https://www.kernel.org/doc/Documentation/x86/boot.txt for the full
// documentation.
// Header field: `boot_flag`. Must contain 0xaa55. This is the closest thing old Linux kernels
// have to a magic number.
const KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
// Header field: `header`. Must contain the magic number `HdrS` (0x5372_6448).
const KERNEL_HDR_MAGIC: u32 = 0x5372_6448;
// Header field: `type_of_loader`. Unless using a pre-registered bootloader (which we aren't), this
// field must be set to 0xff.
const KERNEL_LOADER_OTHER: u8 = 0xff;
// Header field: `kernel_alignment`. Alignment unit required by a relocatable kernel.
const KERNEL_MIN_ALIGNMENT_BYTES: u32 = 0x0100_0000;

// Start address for the EBDA (Extended Bios Data Area). Older computers (like the one this VMM
// emulates) typically use 1 KiB for the EBDA, starting at 0x9fc00.
// See https://wiki.osdev.org/Memory_Map_(x86) for more information.
const EBDA_START: u64 = 0x0009_fc00;
// RAM memory type.
// TODO: this should be bindgen'ed and exported by linux-loader.
// See https://github.com/rust-vmm/linux-loader/issues/51
const E820_RAM: u32 = 1;

#[derive(Debug)]
/// Errors pertaining to boot parameter setup.
pub enum Error {
    /// Invalid E820 configuration.
    E820Configuration,
    /// Highmem start address is past the guest memory end.
    HimemStartPastMemEnd,
    /// Highmem start address is past the MMIO gap end.
    HimemStartPastMmioGapEnd,
    /// The MMIO gap end is past the guest memory end.
    MmioGapPastMemEnd,
}

fn add_e820_entry(
    params: &mut boot_params,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> result::Result<(), Error> {
    if params.e820_entries >= params.e820_table.len() as u8 {
        return Err(Error::E820Configuration);
    }

    params.e820_table[params.e820_entries as usize].addr = addr;
    params.e820_table[params.e820_entries as usize].size = size;
    params.e820_table[params.e820_entries as usize].type_ = mem_type;
    params.e820_entries += 1;

    Ok(())
}

/// Build boot parameters for ELF kernels following the Linux boot protocol.
///
/// # Arguments
///
/// * `guest_memory` - guest memory
/// * `himem_start` - address where high memory starts.
/// * `mmio_gap_start` - address where the MMIO gap starts.
/// * `mmio_gap_end` - address where the MMIO gap ends.
pub fn build_bootparams(
    guest_memory: &GuestMemoryMmap,
    himem_start: GuestAddress,
    mmio_gap_start: GuestAddress,
    mmio_gap_end: GuestAddress,
) -> result::Result<boot_params, Error> {
    let mut params = boot_params::default();

    params.hdr.boot_flag = KERNEL_BOOT_FLAG_MAGIC;
    params.hdr.header = KERNEL_HDR_MAGIC;
    params.hdr.kernel_alignment = KERNEL_MIN_ALIGNMENT_BYTES;
    params.hdr.type_of_loader = KERNEL_LOADER_OTHER;

    // Add an entry for EBDA itself.
    add_e820_entry(&mut params, 0, EBDA_START, E820_RAM)?;

    // Add entries for the usable RAM regions (potentially surrounding the MMIO gap).
    let last_addr = guest_memory.last_addr();
    if last_addr < mmio_gap_start {
        add_e820_entry(
            &mut params,
            himem_start.raw_value() as u64,
            last_addr
                .checked_offset_from(himem_start)
                .ok_or(Error::HimemStartPastMemEnd)?,
            E820_RAM,
        )?;
    } else {
        add_e820_entry(
            &mut params,
            himem_start.raw_value(),
            mmio_gap_end
                .checked_offset_from(himem_start)
                .ok_or(Error::HimemStartPastMmioGapEnd)?,
            E820_RAM,
        )?;

        if last_addr > mmio_gap_end {
            add_e820_entry(
                &mut params,
                mmio_gap_end.raw_value(),
                last_addr
                    .checked_offset_from(mmio_gap_end)
                    .ok_or(Error::HimemStartPastMmioGapEnd)?
                    + 1,
                E820_RAM,
            )?;
        }
    }

    Ok(params)
}
