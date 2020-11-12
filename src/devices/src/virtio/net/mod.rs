// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

mod bindings;
mod device;
mod handler;
mod simple_handler;
pub mod tap;

use std::io;
use std::sync::Arc;

use event_manager::{Error as EvmgrError, MutEventSubscriber, RemoteEndpoint};
use kvm_ioctls::VmFd;
use vmm_sys_util::errno;

use crate::virtio::MmioConfig;

pub use device::Net;

// Values taken from the virtio standard.
pub mod features {
    pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
    pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
    pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
    pub const VIRTIO_NET_F_GUEST_UFO: u64 = 1 << 10;
    pub const VIRTIO_NET_F_HOST_TSO4: u64 = 1 << 11;
    pub const VIRTIO_NET_F_HOST_UFO: u64 = 1 << 14;
}

// Net device ID as defined by the standard.
pub const NET_DEVICE_ID: u32 = 1;

// Prob have to find better names here, but these basically represent the order of the queues.
// If the net device has a single RX/TX pair, then the former has index 0 and the latter 1. When
// the device has multiqueue support, then RX queues have indices 2k, and TX queues 2k+1.
const RXQ_INDEX: u16 = 0;
const TXQ_INDEX: u16 = 1;

#[derive(Debug)]
pub enum Error {
    AlreadyActivated,
    BadFeatures(u64),
    Backend(io::Error),
    Endpoint(EvmgrError),
    EventFd(io::Error),
    QueuesNotValid,
    RegisterIoevent(errno::Error),
    RegisterIrqfd(errno::Error),
    Tap(tap::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct NetArgs<M> {
    pub mem: M,
    pub endpoint: RemoteEndpoint<Box<dyn MutEventSubscriber + Send>>,
    pub vm_fd: Arc<VmFd>,
    pub mmio_cfg: MmioConfig,
    pub tap_name: String,
}
