// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

// We're only providing virtio over MMIO devices for now, but we aim to add PCI support as well.

pub mod block;
pub mod net;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use vm_device::bus::MmioRange;
use vmm_sys_util::eventfd::EventFd;

// Device-independent virtio features.
mod features {
    pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;
    pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;
    pub const VIRTIO_F_IN_ORDER: u64 = 1 << 35;
}

// This bit is set on the device interrupt status when notifying the driver about used
// queue events.
// TODO: There seem to be similar semantics when the PCI transport is used with MSI-X cap
// disabled. Let's figure out at some point if having MMIO as part of the name is necessary.
const VIRTIO_MMIO_INT_VRING: u8 = 0x01;

// The driver will write to the register at this offset in the MMIO region to notify the device
// about available queue events.
const VIRTIO_MMIO_QUEUE_NOTIFY_OFFSET: u64 = 0x50;

// TODO: Make configurable for each device maybe?
const QUEUE_MAX_SIZE: u16 = 256;

#[derive(Copy, Clone)]
pub struct MmioConfig {
    pub range: MmioRange,
    // The interrupt assigned to the device.
    pub gsi: u32,
}

// Simple trait to model the operation of signalling the driver about used events for the given
// queue.
// TODO: See if this needs renaming/changes to be relevant for packed queues as well.
pub trait SignalUsedQueue {
    // TODO: Should this return an error?
    fn signal_used_queue(&self, index: u16);
}

// Uses a single irqfd as the basis of signalling any queue (useful for the MMIO transport, where
// a single interrupt is shared for everything).
pub struct SingleFdSignalQueue {
    pub irqfd: Arc<EventFd>,
    pub interrupt_status: Arc<AtomicU8>,
}

impl SignalUsedQueue for SingleFdSignalQueue {
    fn signal_used_queue(&self, _index: u16) {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING, Ordering::SeqCst);
        self.irqfd
            .write(1)
            .expect("Failed write to eventfd when signalling queue");
    }
}
