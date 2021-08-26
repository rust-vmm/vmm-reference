use std::convert::TryInto;
use vm_device::bus::MmioAddress;
use vm_device::MutDeviceMmio;
use vm_superio::{rtc_pl031::NoEvents, RTC};

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
