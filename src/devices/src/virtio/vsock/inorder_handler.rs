use std::result;

use log::{debug, error, warn};
use vm_memory::GuestAddressSpace;
use vm_virtio::Queue;

use crate::virtio::vsock::{VsockBackend, VsockPacket};
use crate::virtio::SignalUsedQueue;

const RXQ_INDEX: u16 = 0;
const TXQ_INDEX: u16 = 1;

#[derive(Debug)]
pub enum Error {
    Queue(vm_virtio::Error),
}

impl From<vm_virtio::Error> for Error {
    fn from(e: vm_virtio::Error) -> Self {
        Error::Queue(e)
    }
}

// TODO: The event queue is not supported for now.
pub struct InOrderHandler<M: GuestAddressSpace, S, B> {
    pub driver_notify: S,
    pub rxq: Queue<M>,
    pub txq: Queue<M>,
    pub backend: B,
}

// The following comes from Fc; have to double check if it's still something that have to be
// solved.
// TODO: Detect / handle queue deadlock:
// 1. If the driver halts RX queue processing, we'll need to notify `self.backend`, so that it
//    can unregister any EPOLLIN listeners, since otherwise it will keep spinning, unable to consume
//    its EPOLLIN events.

impl<M, S, B> InOrderHandler<M, S, B>
where
    M: GuestAddressSpace,
    S: SignalUsedQueue,
    B: VsockBackend,
{
    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_rx(&mut self) -> result::Result<bool, Error> {
        if !self.backend.has_pending_rx() {
            return Ok(false);
        }

        debug!("vsock: process_rx()");

        let mut have_used = false;

        while let Some(mut chain) = self.rxq.iter()?.next() {
            let used_len = match VsockPacket::from_rx_virtq_head(&mut chain) {
                Ok(mut pkt) => {
                    if self.backend.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        self.rxq.go_to_previous_position();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            have_used = true;
            self.rxq
                .add_used(chain.head_index(), used_len)
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to add available descriptor {}: {}",
                        chain.head_index(),
                        e
                    )
                });
        }

        if have_used {
            self.driver_notify.signal_used_queue(RXQ_INDEX);
        }

        Ok(have_used)
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them
    /// to the backend for processing. Return `true` if descriptors have been added to the used
    /// ring, and `false` otherwise.
    pub fn process_tx(&mut self) -> result::Result<bool, Error> {
        debug!("vsock::process_tx()");

        let mut have_used = false;

        while let Some(mut chain) = self.txq.iter()?.next() {
            let pkt = match VsockPacket::from_tx_virtq_head(&mut chain) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: error reading TX packet: {:?}", e);
                    have_used = true;
                    self.txq
                        .add_used(chain.head_index(), 0)
                        .unwrap_or_else(|e| {
                            error!(
                                "Failed to add available descriptor {}: {}",
                                chain.head_index(),
                                e
                            );
                        });
                    continue;
                }
            };

            if self.backend.send_pkt(&pkt).is_err() {
                self.txq.go_to_previous_position();
                break;
            }

            have_used = true;
            self.txq
                .add_used(chain.head_index(), 0)
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to add available descriptor {}: {}",
                        chain.head_index(),
                        e
                    );
                });
        }

        if have_used {
            self.driver_notify.signal_used_queue(TXQ_INDEX);
        }

        Ok(have_used)
    }
}
