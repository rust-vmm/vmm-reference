// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
#![cfg(target_arch = "x86_64")]
use kvm_bindings::kvm_lapic_state;

// Yanked from byte_order
macro_rules! generate_read_fn {
    ($fn_name: ident, $data_type: ty, $byte_type: ty, $type_size: expr, $endian_type: ident) => {
        pub fn $fn_name(input: &[$byte_type]) -> $data_type {
            assert!($type_size == std::mem::size_of::<$data_type>());
            let mut array = [0u8; $type_size];
            for (byte, read) in array.iter_mut().zip(input.iter().cloned()) {
                *byte = read as u8;
            }
            <$data_type>::$endian_type(array)
        }
    };
}

macro_rules! generate_write_fn {
    ($fn_name: ident, $data_type: ty, $byte_type: ty, $endian_type: ident) => {
        pub fn $fn_name(buf: &mut [$byte_type], n: $data_type) {
            for (byte, read) in buf
                .iter_mut()
                .zip(<$data_type>::$endian_type(n).iter().cloned())
            {
                *byte = read as $byte_type;
            }
        }
    };
}

generate_read_fn!(read_le_i32, i32, i8, 4, from_le_bytes);
generate_write_fn!(write_le_i32, i32, i8, to_le_bytes);

// Defines poached from apicdef.h kernel header.
pub const APIC_LVT0: usize = 0x350;
pub const APIC_LVT1: usize = 0x360;
pub const APIC_MODE_NMI: u32 = 0x4;
pub const APIC_MODE_EXTINT: u32 = 0x7;

/// Errors associated with operations related to interrupts.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The register offset is invalid.
    InvalidRegisterOffset,
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> Result<u32> {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get(range).ok_or(Error::InvalidRegisterOffset)?;
    Ok(read_le_i32(&reg) as u32)
}

pub fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) -> Result<()> {
    // The value that we are setting is a u32, which needs 4 bytes of space.
    // We're here creating a range that can fit the whole value.
    let range = reg_offset..reg_offset + 4;
    let mut reg = klapic
        .regs
        .get_mut(range)
        .ok_or(Error::InvalidRegisterOffset)?;
    write_le_i32(&mut reg, value as i32);
    Ok(())
}

fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    ((reg) & !0x700) | ((mode) << 8)
}

/// Set the APIC delivery mode. Returns an error when the register configuration is invalid.
///
/// # Arguments
/// * `klapic`: The corresponding `kvm_lapic_state` for which to set the delivery mode.
/// * `reg_offset`: The offset that identifies the register for which to set the delivery mode.
///                 Available options exported by this module are: [APIC_LVT0] and [APIC_LVT1].
/// * `mode`: The APIC mode to set. Available options are:
///           [Non Maskable Interrupt - NMI](APIC_MODE_NMI) and
///           [external interrupt - ExtINT](APIC_MODE_EXTINT).
pub fn set_klapic_delivery_mode(
    klapic: &mut kvm_lapic_state,
    reg_offset: usize,
    mode: u32,
) -> Result<()> {
    let reg_value = get_klapic_reg(&klapic, reg_offset)?;
    set_klapic_reg(klapic, reg_offset, set_apic_delivery_mode(reg_value, mode))
}

#[cfg(test)]
mod tests {
    use crate::x86_64::interrupts::{
        get_klapic_reg, set_klapic_delivery_mode, Error, APIC_MODE_EXTINT,
    };
    use kvm_bindings::kvm_lapic_state;

    #[test]
    fn test_reg_offset() {
        // The size of `regs` in `kvm_lapic_state` is 1024. Since we're setting a value of
        // 4 bytes, if we want to set it at offset = 1020 it should fit.
        let offset = 1020;
        let mut klapic = kvm_lapic_state::default();
        assert!(set_klapic_delivery_mode(&mut klapic, offset, APIC_MODE_EXTINT).is_ok());
        assert!(get_klapic_reg(&klapic, offset).is_ok());

        // Setting at the offset og 1021 does not work because 4 bytes don't fit.
        let offset = 1021;
        let mut klapic = kvm_lapic_state::default();
        assert_eq!(
            set_klapic_delivery_mode(&mut klapic, offset, APIC_MODE_EXTINT).unwrap_err(),
            Error::InvalidRegisterOffset
        );
        assert_eq!(
            get_klapic_reg(&klapic, offset).unwrap_err(),
            Error::InvalidRegisterOffset
        );
    }
}
