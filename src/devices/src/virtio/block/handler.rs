// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use event_manager::{EventOps, Events, MutEventSubscriber};
use log::error;
use vm_memory::GuestAddressSpace;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::block::simple_handler::SimpleHandler;
use crate::virtio::SingleFdSignalQueue;

const IOEVENT_DATA: u32 = 0;

// This object simply combines the more generic `SimpleHandler` with a concrete queue signalling
// implementation, and then also implements `MutEventSubscriber` to interact with the event
// manager. `ioeventfd` is the `EventFd` connected to queue notifications coming from the driver.
pub(crate) struct QueueHandler<M: GuestAddressSpace> {
    pub inner: SimpleHandler<M, SingleFdSignalQueue>,
    pub ioeventfd: EventFd,
}

impl<M: GuestAddressSpace> MutEventSubscriber for QueueHandler<M> {
    fn process(&mut self, events: Events, _ops: &mut EventOps) {
        if events.event_set() != EventSet::IN {
            error!("unexpected event_set");
        }

        if events.data() != IOEVENT_DATA {
            error!("unexpected events data {}", events.data());
        }

        if self.ioeventfd.read().is_err() {
            error!("ioeventfd read error")
        }

        if let Err(e) = self.inner.process_queue() {
            error!("error processing block queue {:?}", e);
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.ioeventfd,
            IOEVENT_DATA,
            EventSet::IN,
        ))
        .expect("Failed to init block queue handler");
    }
}
