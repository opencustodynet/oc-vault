extern crate alloc;

use crate::p11;
use alloc::{format, string::String, vec};
use core::{ffi::c_ulong, ptr, str};

pub fn init() -> Result<p11::CK_SESSION_HANDLE, String> {
    let token_label = "opencustody_slot";
    let token_pin = "12345678";

    let rv = unsafe { p11::C_Initialize(ptr::null_mut()) };
    if rv != p11::CKR_OK {
        return Err(format!("C_Initialize failed with error code: {}", rv));
    }

    let slot_id = find_slot_id(token_label).unwrap_or(0);

    let token_label_encoded = label_from_str(token_label);
    let rv = unsafe {
        p11::C_InitToken(
            slot_id,
            token_pin.as_ptr() as *mut u8,
            token_pin.len() as c_ulong,
            token_label_encoded.as_ptr() as *mut u8,
        )
    };
    if rv != p11::CKR_OK {
        return Err(format!("C_InitToken failed with error code: {}", rv));
    }

    let mut session = 0;
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
        return Err(format!("C_OpenSession failed with error code: {}", rv));
    }

    let rv = unsafe {
        p11::C_Login(
            session,
            p11::CKU_SO,
            token_pin.as_ptr() as *mut u8,
            token_pin.len() as c_ulong,
        )
    };
    if rv != p11::CKR_OK {
        return Err(format!("C_Login failed with error code: {}", rv));
    }

    let rv = unsafe {
        p11::C_InitPIN(
            session,
            token_pin.as_ptr() as *mut u8,
            token_pin.len() as c_ulong,
        )
    };
    if rv != p11::CKR_OK {
        return Err(format!("C_InitPIN failed with error code: {}", rv));
    }

    let rv = unsafe { p11::C_Logout(session) };
    if rv != p11::CKR_OK {
        return Err(format!("C_Logout failed with error code: {}", rv));
    }

    let rv = unsafe {
        p11::C_Login(
            session,
            p11::CKU_USER,
            token_pin.as_ptr() as *mut u8,
            token_pin.len() as c_ulong,
        )
    };
    if rv != p11::CKR_OK {
        return Err(format!("C_Login failed with error code: {}", rv));
    }

    Ok(session)
}

pub fn close(session: p11::CK_SESSION_HANDLE) -> Result<(), String> {
    let rv = unsafe { p11::C_Logout(session) };
    if rv != p11::CKR_OK {
        return Err(format!("C_Logout failed with error code: {}", rv));
    }

    let rv = unsafe { p11::C_CloseSession(session) };
    if rv != p11::CKR_OK {
        return Err(format!("C_CloseSession failed with error code: {}", rv));
    }

    let rv = unsafe { p11::C_Finalize(ptr::null_mut()) };
    if rv != p11::CKR_OK {
        return Err(format!("C_Finalize failed with error code: {}", rv));
    }

    Ok(())
}

fn find_slot_id(search_label: &str) -> Result<p11::CK_SLOT_ID, String> {
    let mut slot_count = 0;
    let rv = unsafe { p11::C_GetSlotList(p11::CK_TRUE, ptr::null_mut(), &mut slot_count) };
    if rv != p11::CKR_OK {
        return Err(format!("C_GetSlotList failed with error code: {}", rv));
    }

    let mut slots = vec![0; slot_count as usize];
    let rv = unsafe { p11::C_GetSlotList(p11::CK_TRUE, slots.as_mut_ptr(), &mut slot_count) };
    if rv != p11::CKR_OK {
        return Err(format!("C_GetSlotList failed with error code: {}", rv));
    }

    for slot in slots {
        let mut token_info = p11::CK_TOKEN_INFO::default();
        let rv = unsafe { p11::C_GetTokenInfo(slot, &mut token_info) };
        if rv != p11::CKR_OK {
            return Err(format!("C_GetTokenInfo failed with error code: {}", rv));
        }

        let token_label = str::from_utf8(&token_info.label).unwrap().trim();

        if token_label.eq(search_label) {
            return Ok(slot);
        }
    }

    Err(format!("slot with name {} not found", search_label))
}

fn label_from_str(label: &str) -> [p11::CK_UTF8CHAR; 32] {
    let mut lab: [p11::CK_UTF8CHAR; 32] = [32; 32];
    let mut i = 0;
    for c in label.chars() {
        if i + c.len_utf8() <= 32 {
            let mut buf = [0; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes();
            for b in bytes {
                lab[i] = *b;
                i += 1;
            }
        } else {
            break;
        }
    }
    lab
}
