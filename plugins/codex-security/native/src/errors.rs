use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use std::ffi::{c_char, c_int, CStr};

extern "C" {
    fn strerror(error: c_int) -> *const c_char;
}

#[napi]
pub fn errno_message(error: i32) -> Buffer {
    // Copy the C runtime's message before returning to JavaScript.
    unsafe { CStr::from_ptr(strerror(error)).to_bytes().to_vec().into() }
}
