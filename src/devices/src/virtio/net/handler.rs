// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use event_manager::{EventOps, Events, MutEventSubscriber};
use log::{error, warn};
use vm_memory::GuestAddressSpace;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::SingleFdSignalQueue;

use super::simple_handler::SimpleHandler;

const TAPFD_DATA: u32 = 0;
const RX_IOEVENT_DATA: u32 = 1;
const TX_IOEVENT_DATA: u32 = 2;

pub struct QueueHandler<M: GuestAddressSpace> {
    pub inner: SimpleHandler<M, SingleFdSignalQueue>,
    pub rx_ioevent: EventFd,
    pub tx_ioevent: EventFd,
}

impl<M: GuestAddressSpace> MutEventSubscriber for QueueHandler<M> {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.event_set() != EventSet::IN {
            warn!("unexpected event_set");
        }

        match events.data() {
            TAPFD_DATA => {
                if let Err(e) = self.inner.process_tap() {
                    error!("process tap error {:?}", e);
                }
            }
            RX_IOEVENT_DATA => {
                if self.rx_ioevent.read().is_err() {
                    // Do something?
                }
                if let Err(e) = self.inner.process_rxq() {
                    error!("process rx error {:?}", e);
                }
            }
            TX_IOEVENT_DATA => {
                if self.tx_ioevent.read().is_err() {
                    // Do something?
                }
                if let Err(e) = self.inner.process_txq() {
                    error!("process tx error {:?}", e);
                }
            }
            _ => panic!("unexpected data"),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.inner.tap,
            TAPFD_DATA,
            EventSet::IN | EventSet::EDGE_TRIGGERED,
        ))
        .expect("Unable to add tapfd");

        ops.add(Events::with_data(
            &self.rx_ioevent,
            RX_IOEVENT_DATA,
            EventSet::IN,
        ))
        .expect("Unable to add rxfd");

        ops.add(Events::with_data(
            &self.tx_ioevent,
            TX_IOEVENT_DATA,
            EventSet::IN,
        ))
        .expect("Unable to add txfd");
    }
}
