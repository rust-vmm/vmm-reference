// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

use std::convert::TryInto;
use std::io::{stdin, Read, Write};

use event_manager::{EventOps, Events, MutEventSubscriber};
use vm_device::{
    bus::{PioAddress, PioAddressValue},
    MutDevicePio,
};
use vm_superio::Serial;
use vmm_sys_util::epoll::EventSet;

/// Newtype for implementing `event-manager` functionalities.
pub(crate) struct SerialWrapper<W: Write>(pub Serial<W>);

impl<W: Write> MutEventSubscriber for SerialWrapper<W> {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        // Respond to stdin events.
        // `EventSet::IN` => send what's coming from stdin to the guest.
        // `EventSet::HANG_UP` or `EventSet::ERROR` => deregister the serial input.
        let mut out = [0u8; 32];
        match stdin().read(&mut out) {
            Err(e) => {
                eprintln!("Error while reading stdin: {:?}", e);
            }
            Ok(count) => {
                let event_set = events.event_set();
                let unregister_condition =
                    event_set.contains(EventSet::ERROR) | event_set.contains(EventSet::HANG_UP);
                if count > 0 {
                    if self.0.enqueue_raw_bytes(&out[..count]).is_err() {
                        eprintln!("Failed to send bytes to the guest via serial input");
                    }
                } else if unregister_condition {
                    // Got 0 bytes from serial input; is it a hang-up or error?
                    ops.remove(events)
                        .expect("Failed to unregister serial input");
                }
            }
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // Hook to stdin events.
        ops.add(Events::new(&stdin(), EventSet::IN))
            .expect("Failed to register serial input event");
    }
}

impl<W: Write> MutDevicePio for SerialWrapper<W> {
    fn pio_read(&mut self, _base: PioAddress, offset: PioAddressValue, data: &mut [u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.
        assert_eq!(data.len(), 1);
        data[0] = self.0.read(
            offset
                .try_into()
                .expect("Invalid offset for serial console read"),
        );
    }

    fn pio_write(&mut self, _base: PioAddress, offset: PioAddressValue, data: &[u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.
        assert_eq!(data.len(), 1);
        // TODO #2: log / meter write errors.
        let _ = self.0.write(
            offset
                .try_into()
                .expect("Invalid offset for serial console write"),
            data[0],
        );
    }
}

/// Errors encountered during device operation.
#[derive(Debug)]
pub enum Error {
    /// Failed to create an event manager for device events.
    EventManager(event_manager::Error),
}
