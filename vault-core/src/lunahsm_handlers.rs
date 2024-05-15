extern crate alloc;

use super::handler;
use alloc::alloc::*;
use core::ffi::*;

extern "C" {
    pub fn malloc(__size: u32) -> *mut c_void;
    pub fn free(__ptr: *mut c_void);
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
    return handler(in_buf, in_len, out_buf, out_len);
}
