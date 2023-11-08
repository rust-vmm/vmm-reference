// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause

use event_manager::{EventOps, Events, MutEventSubscriber};
use log::error;
use std::sync::Arc;
use vm_memory::GuestMemoryMmap;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::block::inorder_handler::InOrderQueueHandler;
use crate::virtio::SingleFdSignalQueue;

const IOEVENT_DATA: u32 = 0;

// This object simply combines the more generic `InOrderQueueHandler` with a concrete queue
// signalling implementation based on `EventFd`s, and then also implements `MutEventSubscriber`
// to interact with the event manager. `ioeventfd` is the `EventFd` connected to queue
// notifications coming from the driver.
pub(crate) struct QueueHandler {
    pub mem: Arc<GuestMemoryMmap>,
    pub inner: InOrderQueueHandler<SingleFdSignalQueue>,
    pub ioeventfd: EventFd,
}

impl MutEventSubscriber for QueueHandler {
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let mut error = true;

        // TODO: Have a look at any potential performance impact caused by these conditionals
        // just to be sure.
        if events.event_set() != EventSet::IN {
            error!("unexpected event_set");
        } else if events.data() != IOEVENT_DATA {
            error!("unexpected events data {}", events.data());
        } else if self.ioeventfd.read().is_err() {
            error!("ioeventfd read error")
        } else if let Err(e) = self.inner.process_queue(self.mem.clone()) {
            error!("error processing block queue {:?}", e);
        } else {
            error = false;
        }

        if error {
            ops.remove(events)
                .expect("Failed to remove fd from event handling loop");
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

// TODO: Figure out if unit tests make sense here as well after implementing a generic backend
// abstraction for the `InOrderHandler`.
