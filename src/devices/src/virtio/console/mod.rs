// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

mod device;
mod inorder_handler;
mod queue_handler;

pub use device::Console;

// Console device ID as defined by the standard.
pub const CONSOLE_DEVICE_ID: u32 = 3;

// Numbers that represent the order of the queues for the basic virtio console without multiport
// support.
const RECEIVEQ_INDEX: u16 = 0;
const TRANSMITQ_INDEX: u16 = 1;

#[derive(Debug)]
pub enum Error {
    Virtio(crate::virtio::Error),
    Console(virtio_console::console::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
