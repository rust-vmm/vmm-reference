// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use crate::virtio::console::{RECEIVEQ_INDEX, TRANSMITQ_INDEX};
use crate::virtio::SignalUsedQueue;
use std::io::Write;
use std::result;
use virtio_console::console;
use virtio_console::console::Error::UnexpectedReadOnlyDescriptor;
use virtio_queue::{Queue, QueueStateOwnedT, QueueStateT};
use vm_memory::GuestAddressSpace;

#[derive(Debug)]
pub enum Error {
    GuestMemory(vm_memory::GuestMemoryError),
    Queue(virtio_queue::Error),
    Console(console::Error),
}

impl From<vm_memory::GuestMemoryError> for Error {
    fn from(e: vm_memory::GuestMemoryError) -> Self {
        Error::GuestMemory(e)
    }
}

impl From<virtio_queue::Error> for Error {
    fn from(e: virtio_queue::Error) -> Self {
        Error::Queue(e)
    }
}

impl From<console::Error> for Error {
    fn from(e: console::Error) -> Self {
        Error::Console(e)
    }
}

pub struct InOrderQueueHandler<M: GuestAddressSpace, S: SignalUsedQueue, T: Write> {
    pub driver_notify: S,
    pub transmitq: Queue<M>,
    pub receiveq: Queue<M>,
    pub console: console::Console<T>,
}

impl<M, S, T> InOrderQueueHandler<M, S, T>
where
    M: GuestAddressSpace,
    S: SignalUsedQueue,
    T: Write,
{
    pub fn process_transmitq(&mut self) -> result::Result<(), Error> {
        // This is done in a loop to catch the notifications that might be available when they are
        // enabled again. More details can be found at `Queue::enable_notification`.
        loop {
            self.transmitq.disable_notification()?;

            while let Some(mut chain) = self
                .transmitq
                .state
                .pop_descriptor_chain(self.transmitq.mem.memory())
            {
                self.console.process_transmitq_chain(&mut chain)?;

                self.transmitq.add_used(chain.head_index(), 0)?;

                if self.transmitq.needs_notification()? {
                    self.driver_notify.signal_used_queue(TRANSMITQ_INDEX);
                }
            }
            if !self.transmitq.enable_notification()? {
                break;
            }
        }
        Ok(())
    }

    pub fn process_receiveq(&mut self) -> result::Result<(), Error> {
        // This is done in a loop to catch the notifications that might be available when they are
        // enabled again. More details can be found at `Queue::enable_notification`.
        loop {
            self.receiveq.disable_notification()?;
            while let Some(mut chain) = self
                .receiveq
                .state
                .pop_descriptor_chain(self.receiveq.mem.memory())
            {
                let used_len = match self.console.process_receiveq_chain(&mut chain) {
                    Ok(used_len) => {
                        if used_len == 0 {
                            self.receiveq.state.go_to_previous_position();
                            break;
                        }
                        used_len
                    }
                    Err(UnexpectedReadOnlyDescriptor) => 0,
                    Err(e) => {
                        self.receiveq.state.go_to_previous_position();
                        return Err(Error::Console(e));
                    }
                };

                self.receiveq.add_used(chain.head_index(), used_len)?;

                if self.receiveq.needs_notification()? {
                    self.driver_notify.signal_used_queue(RECEIVEQ_INDEX);
                }
            }
            if self.console.is_input_buffer_empty() || !self.receiveq.enable_notification()? {
                break;
            }
        }
        Ok(())
    }
}
