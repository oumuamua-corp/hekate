// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::ffi;

pub struct CancelToken {
    raw: *mut ffi::HekateCancelToken,
}

// Safety:
// hekate_cancel_request and hekate_cancel_free
// are documented thread-safe by the cdylib.
unsafe impl Send for CancelToken {}
unsafe impl Sync for CancelToken {}

impl CancelToken {
    pub fn new() -> Self {
        // Safety:
        // hekate_cancel_new returns either a valid
        // opaque handle or null on alloc failure.
        let raw = unsafe { ffi::hekate_cancel_new() };
        assert!(!raw.is_null(), "hekate_cancel_new returned null");

        Self { raw }
    }

    pub fn request(&self) {
        // Safety:
        // self.raw non-null since construction;
        // cdylib guarantees thread-safety.
        unsafe { ffi::hekate_cancel_request(self.raw) };
    }

    pub(crate) fn as_ptr(&self) -> *const ffi::HekateCancelToken {
        self.raw as *const _
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for CancelToken {
    fn drop(&mut self) {
        // Safety:
        // matches hekate_cancel_new;
        // called exactly once on drop.
        unsafe { ffi::hekate_cancel_free(self.raw) };
    }
}
