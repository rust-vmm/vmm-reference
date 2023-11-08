// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use std::cell::RefCell;
use std::cmp;
use std::io::{self, Read, Write};
use std::result;

use log::warn;
use virtio_queue::{DescriptorChain, Queue, QueueOwnedT, QueueT};
use vm_memory::{Bytes, GuestMemoryMmap};

use crate::virtio::net::tap::Tap;
use crate::virtio::net::{RXQ_INDEX, TXQ_INDEX};
use crate::virtio::SignalUsedQueue;
use std::sync::Arc;

// According to the standard: "If the VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6 or
// VIRTIO_NET_F_GUEST_UFO features are used, the maximum incoming packet will be to 65550
// bytes long (the maximum size of a TCP or UDP packet, plus the 14 byte ethernet header),
// otherwise 1514 bytes. The 12-byte struct virtio_net_hdr is prepended to this, making for
// 65562 or 1526 bytes." For transmission, the standard states "The header and packet are added
// as one output descriptor to the transmitq, and the device is notified of the new entry".
// We assume the TX frame will not exceed this size either.
const MAX_BUFFER_SIZE: usize = 65562;

#[derive(Debug)]
pub enum Error {
    GuestMemory(vm_memory::GuestMemoryError),
    Queue(virtio_queue::Error),
    Tap(io::Error),
}

impl From<virtio_queue::Error> for Error {
    fn from(e: virtio_queue::Error) -> Self {
        Error::Queue(e)
    }
}

// A simple handler implementation for a RX/TX queue pair, which does not make assumptions about
// the way queue notification is implemented. The backend is not yet generic (we always assume a
// `Tap` object), but we're looking at improving that going forward.
pub struct SimpleHandler<S: SignalUsedQueue> {
    pub mem: Arc<GuestMemoryMmap>,
    pub driver_notify: S,
    pub rxq: Queue,
    pub rxbuf_current: usize,
    pub rxbuf: [u8; MAX_BUFFER_SIZE],
    pub txq: Queue,
    pub txbuf: RefCell<[u8; MAX_BUFFER_SIZE]>,
    pub tap: RefCell<Tap>,
}

impl<S: SignalUsedQueue> SimpleHandler<S> {
    pub fn new(
        mem: Arc<GuestMemoryMmap>,
        driver_notify: S,
        rxq: Queue,
        txq: Queue,
        tap: Tap,
    ) -> Self {
        SimpleHandler {
            mem,
            driver_notify,
            rxq,
            rxbuf_current: 0,
            rxbuf: [0u8; MAX_BUFFER_SIZE],
            txq,
            //inner: RefCell::new(SimpleHandlerInner { txbuf: [0u8; MAX_BUFFER_SIZE], tap }),
            txbuf: RefCell::new([0u8; MAX_BUFFER_SIZE]),
            tap: RefCell::new(tap),
        }
    }

    // Have to see how to approach error handling for the `Queue` implementation in particular,
    // because many situations are not really recoverable. We should consider reporting them based
    // on the  metrics/events solution when they appear, and not propagate them further unless
    // it's really useful/necessary.
    fn write_frame_to_guest(&mut self) -> result::Result<bool, Error> {
        let num_bytes = self.rxbuf_current;

        let mut chain = match self.rxq.iter(self.mem.as_ref())?.next() {
            Some(c) => c,
            _ => return Ok(false),
        };

        let mut count = 0;
        let buf = &mut self.rxbuf[..num_bytes];

        while let Some(desc) = chain.next() {
            let left = buf.len() - count;

            if left == 0 {
                break;
            }

            let len = cmp::min(left, desc.len() as usize);
            chain
                .memory()
                .write_slice(&buf[count..count + len], desc.addr())
                .map_err(Error::GuestMemory)?;

            count += len;
        }

        if count != buf.len() {
            // The frame was too large for the chain.
            warn!("rx frame too large");
        }

        self.rxq
            .add_used(self.mem.as_ref(), chain.head_index(), count as u32)?;

        self.rxbuf_current = 0;

        Ok(true)
    }

    pub fn process_tap(&mut self) -> result::Result<(), Error> {
        loop {
            if self.rxbuf_current == 0 {
                match self.tap.borrow_mut().read(&mut self.rxbuf) {
                    Ok(n) => self.rxbuf_current = n,
                    Err(_) => {
                        // TODO: Do something (logs, metrics, etc.) in response to an error when
                        // reading from tap. EAGAIN means there's nothing available to read anymore
                        // (because we open the TAP as non-blocking).
                        break;
                    }
                }
            }

            if !self.write_frame_to_guest()? && !self.rxq.enable_notification(self.mem.as_ref())? {
                break;
            }
        }

        if self.rxq.needs_notification(self.mem.as_ref())? {
            self.driver_notify.signal_used_queue(RXQ_INDEX);
        }

        Ok(())
    }

    fn send_frame_from_chain(
        &self,
        chain: &mut DescriptorChain<&GuestMemoryMmap>,
    ) -> result::Result<u32, Error> {
        let mut count = 0;

        while let Some(desc) = chain.next() {
            let left = self.txbuf.borrow().len() - count;
            let len = desc.len() as usize;

            if len > left {
                warn!("tx frame too large");
                break;
            }

            chain
                .memory()
                .read_slice(
                    &mut self.txbuf.borrow_mut()[count..count + len],
                    desc.addr(),
                )
                .map_err(Error::GuestMemory)?;

            count += len;
        }

        self.tap
            .borrow_mut()
            .write(&self.txbuf.borrow()[..count])
            .map_err(Error::Tap)?;

        Ok(count as u32)
    }

    pub fn process_txq(&mut self) -> result::Result<(), Error> {
        loop {
            self.txq.disable_notification(self.mem.as_ref())?;

            while let Some(mut chain) = self.txq.iter(self.mem.as_ref())?.next() {
                self.send_frame_from_chain(&mut chain)?;

                self.txq
                    .add_used(self.mem.as_ref(), chain.head_index(), 0)?;

                if self.txq.needs_notification(self.mem.as_ref())? {
                    self.driver_notify.signal_used_queue(TXQ_INDEX);
                }
            }

            if !self.txq.enable_notification(self.mem.as_ref())? {
                return Ok(());
            }
        }
    }

    pub fn process_rxq(&mut self) -> result::Result<(), Error> {
        self.rxq.disable_notification(self.mem.as_ref())?;
        self.process_tap()
    }
}
