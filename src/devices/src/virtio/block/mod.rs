// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

mod device;
mod handler;
// This is taken from Firecracker for now. Hopefully we can replace it with the simple
// abstractions we're trying to start with in upstream, before we develop request execution
// further.
pub mod request;
mod simple_handler;

use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::path::Path;
use std::sync::Arc;

use event_manager::{Error as EvmgrError, MutEventSubscriber, RemoteEndpoint};
use kvm_ioctls::VmFd;
use vmm_sys_util::errno;

use crate::virtio::MmioConfig;

pub use device::Block;

// Block device ID as defined by the standard.
pub const BLOCK_DEVICE_ID: u32 = 2;

// Block device FLUSH feature.
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

const SECTOR_SHIFT: u8 = 9;
// The sector size is 512 bytes.
const SECTOR_SIZE: u64 = 1 << SECTOR_SHIFT;

#[derive(Debug)]
pub enum Error {
    AlreadyActivated,
    BadFeatures(u64),
    Backend(io::Error),
    Endpoint(EvmgrError),
    EventFd(io::Error),
    OpenFile(io::Error),
    QueuesNotValid,
    RegisterIoevent(errno::Error),
    RegisterIrqfd(errno::Error),
    Seek(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

// TODO: Add a helper abstraction to rust-vmm for building the device configuration space.
// The one we build below for the block device contains the minimally required `capacity` member,
// but other fields can be present as well depending on the negotiated features.
fn build_config_space<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let file_size = File::open(path)
        .map_err(Error::OpenFile)?
        .seek(SeekFrom::End(0))
        .map_err(Error::Seek)?;
    // If the file size is actually not a multiple of sector size, then data at the very end
    // will be ignored.
    let num_sectors = file_size >> SECTOR_SHIFT;
    // This has to be in little endian btw.
    Ok(num_sectors.to_be_bytes().to_vec())
}

// Arguments required when building a block device.
// TODO: Add read-only operation support as a quick next step.
pub struct BlockArgs<M> {
    pub mem: M,
    // The device uses this to create and register the queue handler at activation time.
    pub endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    // Used to register irfqds and ioeventfds by the device.
    pub vm_fd: Arc<VmFd>,
    pub mmio_cfg: MmioConfig,
    pub file_path: String,
}
