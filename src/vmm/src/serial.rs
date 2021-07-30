// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

#![cfg(target_arch = "x86_64")]

use std::convert::TryInto;
use std::io::{self, stdin, Read, Write};

use event_manager::{EventOps, Events, MutEventSubscriber};
use vm_device::{
    bus::{PioAddress, PioAddressValue},
    MutDevicePio,
};
use vm_superio::serial::{NoEvents, SerialEvents};
use vm_superio::{Serial, Trigger};
use vmm_sys_util::epoll::EventSet;

use utils::debug;

/// Newtype for implementing `event-manager` functionalities.
pub(crate) struct SerialWrapper<T: Trigger, EV: SerialEvents, W: Write>(pub Serial<T, EV, W>);

impl<T: Trigger, W: Write> MutEventSubscriber for SerialWrapper<T, NoEvents, W> {
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

impl<T: Trigger<E = io::Error>, W: Write> MutDevicePio for SerialWrapper<T, NoEvents, W> {
    fn pio_read(&mut self, _base: PioAddress, offset: PioAddressValue, data: &mut [u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.
        if data.len() != 1 {
            debug!(
                "Serial console invalid data length on PIO read: {}",
                data.len()
            );
        }

        match offset.try_into() {
            Ok(offset) => data[0] = self.0.read(offset),
            Err(_) => debug!("Invalid serial console read offset."),
        }
    }

    fn pio_write(&mut self, _base: PioAddress, offset: PioAddressValue, data: &[u8]) {
        // TODO: this function can't return an Err, so we'll mark error conditions
        // (data being more than 1 byte, offset overflowing an u8) with logs & metrics.
        if data.len() != 1 {
            debug!(
                "Serial console invalid data length on PIO write: {}",
                data.len()
            );
        }

        match offset.try_into() {
            Ok(offset) => {
                let res = self.0.write(offset, data[0]);
                if res.is_err() {
                    debug!("Error writing to serial console: {:#?}", res.unwrap_err())
                }
            }
            Err(_) => debug!("Invalid serial console read offset."),
        }
    }
}

/// Errors encountered during device operation.
#[derive(Debug)]
pub enum Error {
    /// Failed to create an event manager for device events.
    EventManager(event_manager::Error),
}

#[cfg(test)]
mod tests {
    use crate::EventFdTrigger;

    use super::SerialWrapper;

    use std::io::sink;

    use vm_device::{bus::PioAddress, MutDevicePio};
    use vm_superio::Serial;

    #[test]
    fn test_invalid_data_len() {
        let interrupt_evt = EventFdTrigger::new(libc::EFD_NONBLOCK).unwrap();
        let mut serial_console = SerialWrapper(Serial::new(interrupt_evt, sink()));

        // In case the data length is more than 1, the read succeeds as we send
        // to the serial console just the first byte.
        let mut invalid_data = [0, 0];
        let valid_iir_offset = 2;
        serial_console.pio_read(PioAddress(0), valid_iir_offset, invalid_data.as_mut());
        // Check that the emulation added a value to `invalid_data`.
        assert_ne!(invalid_data[0], 0);

        // The same scenario happens for writes.
        serial_console.pio_write(PioAddress(0), valid_iir_offset, &invalid_data);

        // Check that passing an invalid offset does not result in a crash.
        let data = [0];
        let invalid_offset = u16::MAX;
        serial_console.pio_write(PioAddress(0), invalid_offset, &data);
    }
}
