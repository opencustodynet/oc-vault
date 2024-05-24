#![cfg_attr(
    feature = "lunahsm",
    no_std,
    feature(alloc_error_handler, fmt_internals, lang_items),
    allow(internal_features)
)]
mod api;
#[cfg(feature = "lunahsm")]
mod lunahsm_handlers;

extern crate alloc;
use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{ptr, slice};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use shared::{p11, FM_MAX_BUFFER_SIZE};

pub fn handler(in_buf: *mut u8, in_len: u32, out_buf: *mut u8, out_len: &mut u32) -> u32 {
    let serialized_response = if in_len as usize > FM_MAX_BUFFER_SIZE {
        api::get_error_response(&format!(
            "HSM buffer size limit is {} but serialized request size is {}",
            FM_MAX_BUFFER_SIZE, in_len
        ))
    } else {
        let in_buf = unsafe { slice::from_raw_parts(in_buf, in_len as usize) };
        let serialized_request = in_buf.to_vec();

        let serialized_response = api::dispatcher(serialized_request);

        if serialized_response.len() > FM_MAX_BUFFER_SIZE {
            api::get_error_response(&format!(
                "HSM buffer size limit is {} but serialized response size is {}",
                FM_MAX_BUFFER_SIZE,
                serialized_response.len()
            ))
        } else {
            serialized_response
        }
    };

    unsafe {
        ptr::copy(
            serialized_response.as_ptr(),
            out_buf,
            serialized_response.len(),
        );
    }
    *out_len = serialized_response.len() as u32;

    0
}
