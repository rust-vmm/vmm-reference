use vm_device::MutDeviceMmio;
use vm_device::bus::MmioAddress;
use event_manager::{MutEventSubscriber, Events, EventOps};
use std::io::Write;

// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause


use std::sync::Arc;
use std::time::Instant;

// As you can see in
//  https://static.docs.arm.com/ddi0224/c/real_time_clock_pl031_r1p3_technical_reference_manual_DDI0224C.pdf
//  at section 3.2 Summary of RTC registers, the total size occupied by this
//  device is 0x000 -> 0xFFC + 4 = 0x1000 bytes.

// From 0x0 to 0x1C we have following registers:
const RTCDR: u16 = 0x000; // Data Register (RO).
const RTCMR: u16 = 0x004; // Match Register.
const RTCLR: u16 = 0x008; // Load Register.
const RTCCR: u16 = 0x00C; // Control Register.
const RTCIMSC: u16 = 0x010; // Interrupt Mask Set or Clear Register.
const RTCRIS: u16 = 0x014; // Raw Interrupt Status (RO).
const RTCMIS: u16 = 0x018; // Masked Interrupt Status (RO).
const RTCICR: u16 = 0x01C; // Interrupt Clear Register (WO).

// From 0x020 to 0xFDC => reserved space.

// From 0xFE0 to 0xFFF => Peripheral and PrimeCell Identification Registers
//  These are read-only registers, so we store their values in a constant array.
//  The values are found in the 'Reset value' column of Table 3.1 (Summary of
//  RTC registers) in the the reference manual linked above.
const AMBA_IDS: [u8; 8] = [0x31, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

// Since we are specifying the AMBA IDs in an array, instead of in individual
// registers, these constants bound the register addresses where these IDs
// would normally be located.
const AMBA_ID_LOW: u16 = 0xFE0;
const AMBA_ID_HIGH: u16 = 0xFFF;

use std::time::{SystemTime, UNIX_EPOCH};
use std::convert::TryInto;

/// Defines a series of callbacks that are invoked in response to the occurrence of specific
/// failure or missed events as part of the RTC operation (e.g., write to an invalid offset). The
/// methods below can be implemented by a backend that keeps track of such events by incrementing
/// metrics, logging messages, or any other action.
///
/// We're using a trait to avoid constraining the concrete characteristics of the backend in
/// any way, enabling zero-cost abstractions and use case-specific implementations.
pub trait RTCEvents {
    /// The driver attempts to read from an invalid offset.
    fn invalid_read(&self);

    /// The driver attempts to write to an invalid offset.
    fn invalid_write(&self);
}

/// Provides a no-op implementation of `RTCEvents` which can be used in situations that
/// do not require logging or otherwise doing anything in response to the events defined
/// as part of `RTCEvents`.
pub struct NoEvents;

impl RTCEvents for NoEvents {
    fn invalid_read(&self) {}
    fn invalid_write(&self) {}
}

impl<EV: RTCEvents> RTCEvents for Arc<EV> {
    fn invalid_read(&self) {
        self.as_ref().invalid_read();
    }

    fn invalid_write(&self) {
        self.as_ref().invalid_write();
    }
}

/// A PL031 Real Time Clock (RTC) that emulates a long time base counter.
///
/// This structure emulates the registers for the RTC.
///
/// # Example
///
/// ```rust
/// # use std::thread;
/// # use std::io::Error;
/// # use std::ops::Deref;
/// # use std::time::{Instant, Duration, SystemTime, UNIX_EPOCH};
/// # use vm_superio::RTC;
///
/// let mut data = [0; 4];
/// let mut rtc = RTC::new();
/// const RTCDR: u16 = 0x0; // Data Register.
/// const RTCLR: u16 = 0x8; // Load Register.
///
/// // Write system time since UNIX_EPOCH in seconds to the load register.
/// let v = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
/// data = (v as u32).to_le_bytes();
/// rtc.write(RTCLR, &data);
///
/// // Read the value back out of the load register.
/// rtc.read(RTCLR, &mut data);
/// assert_eq!((v as u32), u32::from_le_bytes(data));
///
/// // Sleep for 1.5 seconds to let the counter tick.
/// let delay = Duration::from_millis(1500);
/// thread::sleep(delay);
///
/// // Read the current RTC value from the Data Register
/// rtc.read(RTCDR, &mut data);
/// assert!(u32::from_le_bytes(data) > (v as u32));
/// ```
pub struct RTC<EV: RTCEvents> {
    // Counts up from 1 on reset at 1Hz (emulated).
    counter: Instant,

    // The offset value applied to the counter to get the RTC value.
    lr: u32,

    // The MR register is used for implementing the RTC alarm. A
    // real time clock alarm is a feature that can be used to allow
    // a computer to 'wake up' after shut down to execute tasks
    // every day or on a certain day. It can sometimes be found in
    // the 'Power Management' section of a motherboard's BIOS setup.
    // This is not currently implemented, so we raise an error.
    // TODO: Implement the match register functionality.
    mr: u32,

    // The interrupt mask.
    imsc: u32,

    // The raw interrupt value.
    ris: u32,

    // Used for tracking the occurrence of significant events.
    events: EV,
}

impl RTC<NoEvents> {
    /// Creates a new `AMBA PL031 RTC` instance without any metric
    /// capabilities.
    ///
    /// # Example
    ///
    /// You can see an example of how to use this function in the
    /// [`Example` section from `RTC`](struct.RTC.html#example).
    pub fn new() -> RTC<NoEvents> {
        Self::with_events(NoEvents)
    }
}

impl Default for RTC<NoEvents> {
    fn default() -> Self {
        Self::new()
    }
}

impl<EV: RTCEvents> RTC<EV> {
    /// Creates a new `AMBA PL031 RTC` instance and invokes the `rtc_events`
    /// implementation of `RTCEvents` during operation.
    ///
    /// # Arguments
    /// * `rtc_events` - The `RTCEvents` implementation used to track the occurrence
    ///                  of failure or missed events in the RTC operation.
    pub fn with_events(rtc_events: EV) -> Self {
        RTC {
            // Counts up from 1 on reset at 1Hz (emulated).
            counter: Instant::now(),

            // The load register is initialized to zero.
            lr: 0,

            // The match register is initialised to zero (not currently used).
            // TODO: Implement the match register functionality.
            mr: 0,

            // The interrupt mask is initialised as not set.
            imsc: 0,

            // The raw interrupt is initialised as not asserted.
            ris: 0,

            // A struct implementing RTCEvents for tracking the occurrence of
            // significant events.
            events: rtc_events,
        }
    }

    /// Provides a reference to the RTC events object.
    pub fn events(&self) -> &EV {
        &self.events
    }

    fn get_rtc_value(&self) -> u32 {
        // Add the counter offset to the seconds elapsed since reset.
        // Using wrapping_add() eliminates the possibility of a panic
        // and makes the desired behaviour (a wrap) explicit.
        let epoch_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime::duration_since failed");
        epoch_time.as_secs() as u32
    }

    /// Handles a write request from the driver at `offset` offset from the
    /// base register address.
    ///
    /// # Arguments
    /// * `offset` - The offset from the base register specifying
    ///              the register to be written.
    /// * `data` - The little endian, 4 byte array to write to the register
    ///
    /// # Example
    ///
    /// You can see an example of how to use this function in the
    /// [`Example` section from `RTC`](struct.RTC.html#example).
    pub fn write(&mut self, offset: u16, data: &[u8; 4]) {
        let val = u32::from_le_bytes(*data);

        match offset {
            RTCMR => {
                // Set the match register.
                // TODO: Implement the match register functionality.
                self.mr = val;
            }
            RTCLR => {
                // Writing to the load register adjusts both the load register
                // and the counter to ensure that a write to RTCLR followed by
                // an immediate read of RTCDR will return the loaded value.
                self.counter = Instant::now();
                self.lr = val;
            }
            RTCCR => {
                // Writing 1 to the control register resets the RTC value,
                // which means both the counter and load register are reset.
            }
            RTCIMSC => {
                // Set or clear the interrupt mask.
                self.imsc = val & 1;
            }
            RTCICR => {
                // Writing 1 clears the interrupt; however, since the match
                // register is unimplemented, this should never be necessary.
                self.ris &= !val;
            }
            _ => {
                // RTCDR, RTCRIS, and RTCMIS are read-only, so writes to these
                // registers or to an invalid offset are ignored; however,
                // We increment the invalid_write() method of the events struct.
                self.events.invalid_write();
            }
        };
    }

    /// Handles a read request from the driver at `offset` offset from the
    /// base register address.
    ///
    /// # Arguments
    /// * `offset` - The offset from the base register specifying
    ///              the register to be read.
    /// * `data` - The little-endian, 4 byte array storing the read value.
    ///
    /// # Example
    ///
    /// You can see an example of how to use this function in the
    /// [`Example` section from `RTC`](struct.RTC.html#example).
    pub fn read(&mut self, offset: u16, data: &mut [u8; 4]) {
        let v = if (AMBA_ID_LOW..=AMBA_ID_HIGH).contains(&offset) {
            let index = ((offset - AMBA_ID_LOW) >> 2) as usize;
            u32::from(AMBA_IDS[index])
        } else {
            match offset {
                RTCDR => {
                    self.get_rtc_value()
                },
                RTCMR => {
                    // Read the match register.
                    // TODO: Implement the match register functionality.
                    self.mr
                }
                RTCLR => self.lr,
                RTCCR => 1, // RTC is always enabled.
                RTCIMSC => self.imsc,
                RTCRIS => self.ris,
                RTCMIS => self.ris & self.imsc,
                _ => {
                    // RTCICR is write only.  For reads of this register or
                    // an invalid offset, call the invalid_read method of the
                    // events struct and return.
                    self.events.invalid_read();
                    return;
                }
            }
        };

        *data = v.to_le_bytes();
    }
}


pub struct RTCWrapper(pub RTC<NoEvents>);

impl MutDeviceMmio for RTCWrapper {
    fn mmio_read(&mut self, _base: MmioAddress, offset: u64, data: &mut [u8]) {
        if data.len() == 4 {
            self.0.read(offset as u16, data.try_into().unwrap());
        }
    }

    fn mmio_write(&mut self, _base: MmioAddress, offset: u64, data: &[u8]) {
        if data.len() == 4 {
            self.0.write(offset as u16, data.try_into().unwrap());
        }
    }
}
