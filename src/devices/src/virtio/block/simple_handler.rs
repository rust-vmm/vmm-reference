// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::result;

use log::warn;
use vm_memory::{self, Bytes, GuestAddressSpace};
use vm_virtio::{DescriptorChain, Queue};

use crate::virtio::block::request::{DiskProperties, Request};
use crate::virtio::SignalUsedQueue;

#[derive(Debug)]
pub enum Error {
    GuestMemory(vm_memory::GuestMemoryError),
    Queue(vm_virtio::Error),
}

impl From<vm_memory::GuestMemoryError> for Error {
    fn from(e: vm_memory::GuestMemoryError) -> Self {
        Error::GuestMemory(e)
    }
}

impl From<vm_virtio::Error> for Error {
    fn from(e: vm_virtio::Error) -> Self {
        Error::Queue(e)
    }
}

// This object is used to process the queue of a block device without making any assumptions
// about the notification mechanism. We're using the backend from Firecracker for now (the
// `DiskProperties` object), but the aim is to have a way of working with generic backends
// to turn this into a more useful building block.
pub struct SimpleHandler<M: GuestAddressSpace, S: SignalUsedQueue> {
    pub driver_notify: S,
    pub queue: Queue<M>,
    pub disk: DiskProperties,
}

impl<M: GuestAddressSpace, S: SignalUsedQueue> SimpleHandler<M, S> {
    fn process_chain(&mut self, mut chain: DescriptorChain<M>) -> result::Result<(), Error> {
        match Request::parse(&mut chain) {
            Ok(request) => {
                let len;
                // TODO: The executor could actually write the status itself, right?
                let status = match request.execute(&mut self.disk, chain.memory()) {
                    Ok(l) => {
                        len = l;
                        // VIRTIO_BLK_S_OK defined as 0 in the standard.
                        0
                    }
                    Err(e) => {
                        warn!("failed to execute block request: {:?}", e);
                        len = 1;
                        e.status()
                    }
                };

                // An interesting question is how to actually handle errors in the following
                // operations. They are not supposed to show up during normal operation,
                // and usually mean the device is no longer usable.

                chain
                    .memory()
                    .write_obj(status as u8, request.status_addr)?;

                self.queue.add_used(chain.head_index(), len)?;
            }
            Err(e) => {
                warn!("block request parse error: {:?}", e);
            }
        }

        if self.queue.needs_notification()? {
            self.driver_notify.signal_used_queue(0);
        }

        Ok(())
    }

    pub fn process_queue(&mut self) -> result::Result<(), Error> {
        // To see why this is done in a loop, please look at the `Queue::enable_notification`
        // comments in `vm_virtio`.
        loop {
            self.queue.disable_notification()?;

            while let Some(chain) = self.queue.iter()?.next() {
                self.process_chain(chain)?;
            }

            if !self.queue.enable_notification()? {
                break;
            }
        }

        Ok(())
    }
}
