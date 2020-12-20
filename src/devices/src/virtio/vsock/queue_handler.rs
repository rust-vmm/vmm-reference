use event_manager::{EventOps, Events, MutEventSubscriber};
use log::{error, warn};
use vm_memory::GuestAddressSpace;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::virtio::vsock::VsockBackend;
use crate::virtio::SingleFdSignalQueue;

use super::inorder_handler::InOrderHandler;

const BACKEND_DATA: u32 = 0;
const RX_IOEVENT_DATA: u32 = 1;
const TX_IOEVENT_DATA: u32 = 2;

pub struct QueueHandler<M: GuestAddressSpace, B> {
    pub inner: InOrderHandler<M, SingleFdSignalQueue, B>,
    pub rx_ioevent: EventFd,
    pub tx_ioevent: EventFd,
}

impl<M, B> QueueHandler<M, B>
where
    M: GuestAddressSpace,
    B: VsockBackend,
{
    fn handle_rxq_event(&mut self, event_set: EventSet) -> bool {
        if event_set != EventSet::IN {
            warn!("vsock: rxq unexpected event {:?}", event_set);
            return false;
        }

        if let Err(e) = self.rx_ioevent.read() {
            warn!("Failed to get vsock rx queue event: {:?}", e);
            return false;
        }

        if let Err(e) = self.inner.process_rx() {
            error!("vosck: process_rx error {:?}", e);
            return false;
        }

        true
    }

    fn process_tx_and_rx(&mut self) -> bool {
        if let Err(e) = self.inner.process_tx() {
            error!("vsock: process_tx error {:?}", e);
            return false;
        }

        // The backend may have queued up responses to the packets we sent during
        // TX queue processing. If that happened, we need to fetch those responses
        // and place them into RX buffers.
        if let Err(e) = self.inner.process_rx() {
            error!("vosck: process_rx error {:?}", e);
            return false;
        }

        true
    }

    fn handle_txq_event(&mut self, event_set: EventSet) -> bool {
        if event_set != EventSet::IN {
            warn!("vsock: txq unexpected event {:?}", event_set);
            return false;
        }

        if let Err(e) = self.tx_ioevent.read() {
            error!("Failed to get vsock tx queue event: {:?}", e);
            return false;
        }

        self.process_tx_and_rx()
    }

    fn notify_backend(&mut self, event_set: EventSet) -> bool {
        self.inner.backend.notify(event_set);
        // After the backend has been kicked, it might've freed up some resources, so we
        // can attempt to send it more data to process. In particular, if `backend.send_pkt()`
        // halted the TX queue processing at some point in the past, now is the time to try
        // walking the  TX queue again.
        self.process_tx_and_rx()
    }
}

impl<M, B> MutEventSubscriber for QueueHandler<M, B>
where
    M: GuestAddressSpace,
    B: VsockBackend,
{
    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let event_set = events.event_set();
        let is_ok = match events.data() {
            RX_IOEVENT_DATA => self.handle_rxq_event(event_set),
            TX_IOEVENT_DATA => self.handle_txq_event(event_set),
            BACKEND_DATA => self.notify_backend(event_set),
            _ => {
                error!("vsock: invalid events.data()");
                false
            }
        };

        // On error, unsubscribe the device events to stop all processing.
        if !is_ok {
            // TODO: Is there a nicer way of performing the unsubscription?
            ops.remove(Events::empty(&self.rx_ioevent))
                .and(ops.remove(Events::empty(&self.tx_ioevent)))
                .and(ops.remove(Events::empty(&self.inner.backend)))
                .expect("failed to remove vsock events");
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        ops.add(Events::with_data(
            &self.inner.backend,
            BACKEND_DATA,
            self.inner.backend.get_polled_evset(),
        ))
        .expect("unable to add backend events");

        ops.add(Events::with_data(
            &self.rx_ioevent,
            RX_IOEVENT_DATA,
            EventSet::IN,
        ))
        .expect("unable to add rxfd");

        ops.add(Events::with_data(
            &self.tx_ioevent,
            TX_IOEVENT_DATA,
            EventSet::IN,
        ))
        .expect("unable to add txfd");
    }
}
