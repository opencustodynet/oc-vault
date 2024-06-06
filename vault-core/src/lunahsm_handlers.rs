extern crate alloc;

use alloc::{
    alloc::{GlobalAlloc, Layout},
    format,
    vec::Vec,
};
use core::ffi::*;
use core::{ptr, slice};
use serde_json::Value;
use shared::{p11, FM_MAX_BUFFER_SIZE};

extern "C" {
    pub fn malloc(__size: u32) -> *mut c_void;
    pub fn free(__ptr: *mut c_void);
    pub fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32;
}

/// The global allocator type.
#[derive(Default)]
pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size() as u32) as *mut u8
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr as *mut c_void);
    }
}

/// If there is an out of memory error, just panic.
#[alloc_error_handler]
fn allocator_error(_layout: Layout) -> ! {
    panic!("out of memory");
}

/// The static global allocator.
#[global_allocator]
static GLOBAL_ALLOCATOR: Allocator = Allocator;

#[no_mangle]
pub extern "C" fn bcmp(s1: *const c_void, s2: *const c_void, n: usize) -> i32 {
    unsafe { memcmp(s1, s2, n) }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _Unwind_Resume() {}

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[no_mangle]
pub unsafe extern "C" fn handler_c(
    in_buf: *mut u8,
    in_len: u32,
    out_buf: *mut u8,
    out_len: &mut u32,
) -> u32 {
    let in_buf = unsafe { slice::from_raw_parts(in_buf, in_len as usize) };
    let serialized_request = in_buf.to_vec();

    let serialized_response = match handler_rust(serialized_request) {
        Ok(serialized_response) => serialized_response,
        Err(serialized_error_response) => serialized_error_response,
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

fn handler_rust(serialized_request: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
    let mut serialized_request = serialized_request;

    // Extract the slot_id from serialized_request
    let slot_id = match serialized_request.get(0..8) {
        Some(slot_id_bytes) => u64::from_be_bytes(match slot_id_bytes.try_into() {
            Ok(slot_id_bytes) => slot_id_bytes,
            Err(_) => {
                return Err(get_error_response_bytes("Invalid slot_id"));
            }
        }),
        None => {
            return Err(get_error_response_bytes("Missing slot_id"));
        }
    };

    let slot_id: p11::CK_SLOT_ID = match slot_id.try_into() {
        Ok(slot_id) => slot_id,
        Err(_) => {
            return Err(get_error_response_bytes("Invalid slot_id"));
        }
    };

    // Remove the slot_id from serialized_request
    serialized_request.drain(0..8);

    // Open a p11 session
    let mut session: p11::CK_SESSION_HANDLE = 0;
    let rv = unsafe {
        p11::C_OpenSession(
            slot_id,
            p11::CKF_SERIAL_SESSION | p11::CKF_RW_SESSION,
            ptr::null_mut(),
            None,
            &mut session,
        )
    };
    if rv != p11::CKR_OK {
        return Err(get_error_response_bytes(&format!(
            "C_OpenSession failed with error code: {}",
            rv
        )));
    }

    // Deserialize the JSON data into a Value
    let request_json: Value = match serde_json::from_slice(&serialized_request) {
        Ok(req) => req,
        Err(e) => {
            return Err(get_error_response_bytes(&format!(
                "Failed to deserialize request: {}",
                e
            )))
        }
    };

    // Dispatch the request
    let response_json = super::dispatch(session, request_json);

    // Serialize the JSON data into a Vec<u8>
    let serialized_response = match serde_json::to_vec(&response_json) {
        Ok(response) => response,
        Err(e) => {
            return Err(get_error_response_bytes(&format!(
                "Failed to serialize response: {}",
                e
            )))
        }
    };

    // Check max buffer size
    if serialized_response.len() > FM_MAX_BUFFER_SIZE {
        return Err(get_error_response_bytes(&format!(
            "HSM buffer size limit is {} but serialized response size is {}",
            FM_MAX_BUFFER_SIZE,
            serialized_response.len()
        )));
    }

    // return the serialized response
    Ok(serialized_response)
}

fn get_error_response_bytes(message: &str) -> Vec<u8> {
    serde_json::to_vec(&super::get_error_response(message)).unwrap()
}
