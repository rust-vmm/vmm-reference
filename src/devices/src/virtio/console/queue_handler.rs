// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use crate::virtio::console::Error;
use event_manager::{EventOps, Events, MutEventSubscriber};
use log::error;
use std::io::{stdin, Read, Stdout};
use vm_memory::GuestAddressSpace;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::console::inorder_handler::InOrderQueueHandler;
use crate::virtio::SingleFdSignalQueue;

const STDIN_EVENT: u32 = 0;
const TRANSMITQ_EVENT: u32 = 1;
const RECEIVEQ_EVENT: u32 = 2;

const STDIN_BUFFER_SIZE: usize = 1024;

// This object simply combines the more generic `ConsoleHandler` with a concrete queue
// signalling implementation based on `EventFd`s, and then also implements `MutEventSubscriber`
// to interact with the event manager. `transmitqfd` and `receiveqfd` are connected to queue
// notifications coming from the driver.
pub(crate) struct QueueHandler<M: GuestAddressSpace> {
    pub inner: InOrderQueueHandler<M, SingleFdSignalQueue, Stdout>,
    pub transmitqfd: EventFd,
    pub receiveqfd: EventFd,
}

impl<M: GuestAddressSpace> MutEventSubscriber for QueueHandler<M> {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        match events.data() {
            STDIN_EVENT => {
                let mut out = [0u8; STDIN_BUFFER_SIZE];
                loop {
                    match stdin().read(&mut out) {
                        Err(e) => {
                            error!("Error while reading stdin: {:?}", e);
                            break;
                        }
                        Ok(count) => {
                            let event_set = events.event_set();
                            let unregister_condition = event_set.contains(EventSet::ERROR)
                                | event_set.contains(EventSet::HANG_UP);
                            if count > 0 {
                                // Send bytes if the `input_buffer` is full.
                                if self.inner.console.available_capacity() < count {
                                    if let Err(e) = self.inner.process_receiveq() {
                                        error!("Receiveq processing failed: {:?}", e);
                                    }
                                }
                                self.inner
                                    .console
                                    .enqueue_data(&mut out[..count].to_vec())
                                    .map_err(Error::Console)
                                    .unwrap();

                                // Send bytes if input sequence is over.
                                if count < STDIN_BUFFER_SIZE {
                                    if let Err(e) = self.inner.process_receiveq() {
                                        error!("Receiveq processing failed: {:?}", e);
                                    }
                                    break;
                                }
                            } else if unregister_condition {
                                // Got 0 bytes from serial input; is it a hang-up or error?
                                ops.remove(events)
                                    .expect("Failed to unregister serial input");
                                break;
                            }
                        }
                    }
                }
            }
            TRANSMITQ_EVENT => {
                if let Err(e) = self.transmitqfd.read() {
                    error!("Could not read transmitq event fd: {:?}", e);
                } else if let Err(e) = self.inner.process_transmitq() {
                    error!("Transmitq processing failed: {:?}", e);
                }
            }
            RECEIVEQ_EVENT => {
                if let Err(e) = self.receiveqfd.read() {
                    error!("Could not read receiveq event fd: {:?}", e);
                } else if let Err(e) = self.inner.process_receiveq() {
                    error!("Receiveq processing failed: {:?}", e);
                }
            }
            _ => {
                error!(
                    "Received unknown event data for virtio console: {}",
                    events.data()
                );
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(&stdin(), STDIN_EVENT, EventSet::IN))
            .expect("Failed to register stdin event");

        ops.add(Events::with_data(
            &self.transmitqfd,
            TRANSMITQ_EVENT,
            EventSet::IN,
        ))
        .expect("Failed to register transmitq event");

        ops.add(Events::with_data(
            &self.receiveqfd,
            RECEIVEQ_EVENT,
            EventSet::IN,
        ))
        .expect("Failed to register receiveq event");
    }
}
