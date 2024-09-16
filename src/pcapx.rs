use std::cell::UnsafeCell;
use std::sync::Arc;
use pcap::{Active, Capture};
use crate::eap::Status;
use crate::eap::Status::WaitingLoop;

pub struct SharedCapture {
    cap: UnsafeCell<Box<Capture<Active>>>,
    status: UnsafeCell<Status>
}

unsafe impl Sync for SharedCapture {}

impl SharedCapture {
    pub fn new(cap: Capture<Active>) -> Arc<Self> {
        Arc::new(SharedCapture {
            cap: UnsafeCell::new(Box::new(cap)),
            status: UnsafeCell::new(WaitingLoop)
        })
    }

    pub fn set_cap(&self, cap: Capture<Active>) {
        unsafe { *self.cap.get() = Box::new(cap); }
    }

    pub fn cap_mut(&self) -> &mut Capture<Active> {
        unsafe { &mut *self.cap.get() }
    }

    pub fn status(&self) -> Status {
        unsafe { *self.status.get() }
    }

    pub fn set_status(&self, status: Status) {
        unsafe { *self.status.get() = status; }
    }
}