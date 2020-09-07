// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

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

generate_read_fn!(read_le_u16, u16, u8, 2, from_le_bytes);
generate_read_fn!(read_le_u32, u32, u8, 4, from_le_bytes);
generate_read_fn!(read_le_u64, u64, u8, 8, from_le_bytes);
generate_read_fn!(read_le_i32, i32, i8, 4, from_le_bytes);

generate_read_fn!(read_be_u16, u16, u8, 2, from_be_bytes);
generate_read_fn!(read_be_u32, u32, u8, 4, from_be_bytes);

generate_write_fn!(write_le_u16, u16, u8, to_le_bytes);
generate_write_fn!(write_le_u32, u32, u8, to_le_bytes);
generate_write_fn!(write_le_u64, u64, u8, to_le_bytes);
generate_write_fn!(write_le_i32, i32, i8, to_le_bytes);

generate_write_fn!(write_be_u16, u16, u8, to_be_bytes);
generate_write_fn!(write_be_u32, u32, u8, to_be_bytes);

/// Errors thrown while configuring the LAPIC.
#[derive(Debug)]
pub enum Error {
    /// Failure in retrieving the LAPIC configuration.
    GetLapic(kvm_ioctls::Error),
    /// Failure in modifying the LAPIC configuration.
    SetLapic(kvm_ioctls::Error),
}
type Result<T> = std::result::Result<T, Error>;

// Defines poached from apicdef.h kernel header.
pub const APIC_LVT0: usize = 0x350;
pub const APIC_LVT1: usize = 0x360;
pub const APIC_MODE_NMI: u32 = 0x4;
pub const APIC_MODE_EXTINT: u32 = 0x7;

pub fn get_klapic_reg(klapic: &kvm_lapic_state, reg_offset: usize) -> u32 {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get(range).expect("get_klapic_reg range");
    read_le_i32(&reg[..]) as u32
}

pub fn set_klapic_reg(klapic: &mut kvm_lapic_state, reg_offset: usize, value: u32) {
    let range = reg_offset..reg_offset + 4;
    let reg = klapic.regs.get_mut(range).expect("set_klapic_reg range");
    write_le_i32(&mut reg[..], value as i32)
}

pub fn set_apic_delivery_mode(reg: u32, mode: u32) -> u32 {
    (((reg) & !0x700) | ((mode) << 8))
}
