use super::*;

pub fn get_session() -> Result<p11::CK_SESSION_HANDLE, String> {
    let token_label = "opencustody_slot";
    let token_pin = "12345678";

    let rv = unsafe { p11::C_Initialize(ptr::null_mut()) };
    if rv != p11::CKR_OK {
        return Err(format!("C_Initialize failed with error code: {}", rv));
    }

    let slot_id = find_slot_id(token_label)?;

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
            p11::CKU_USER,
            token_pin.as_ptr() as *mut u8,
            token_pin.len() as u64,
        )
    };
    if rv != p11::CKR_OK {
        return Err(format!("C_Login failed with error code: {}", rv));
    }

    Ok(session)
}

fn find_slot_id(search_label: &str) -> Result<u64, String> {
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

        let token_label = std::str::from_utf8(&token_info.label).unwrap().trim();

        if token_label.eq(search_label) {
            return Ok(slot);
        }
    }

    Err(format!("slot with name {} not found", search_label))
}
