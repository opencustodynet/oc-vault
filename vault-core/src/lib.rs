#![cfg_attr(
    feature = "lunahsm",
    no_std,
    feature(alloc_error_handler, fmt_internals, lang_items),
    allow(internal_features)
)]

#[cfg(feature = "lunahsm")]
mod lunahsm_handlers;

pub fn handler(in_buf: *mut u8, in_len: u32, out_buf: *mut u8, out_len: &mut u32) -> u32 {
    let in_buf = unsafe { core::slice::from_raw_parts(in_buf, in_len as usize) };
    let out_buf = unsafe { core::slice::from_raw_parts_mut(out_buf, *out_len as usize) };

    let in_str = core::str::from_utf8(in_buf).unwrap();
    let out_str = in_str.to_uppercase();

    let out_bytes = out_str.as_bytes();
    let out_len2 = out_bytes.len();

    out_buf[..out_len2].copy_from_slice(out_bytes);
    *out_len = out_len2 as u32;

    0
}
