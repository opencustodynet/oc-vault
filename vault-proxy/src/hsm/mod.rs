use core::ptr;
use core::slice;
use shared::{p11, FM_MAX_BUFFER_SIZE};

#[cfg(feature = "lunahsm")]
mod md;

#[cfg(feature = "lunahsm")]
const FM_NAME: &str = "opencustody_fm";

pub struct HsmConnection {
    session: u64,
    fm_slot_id: u64,
    #[cfg(feature = "lunahsm")]
    adapter_num: u32,
    #[cfg(feature = "lunahsm")]
    fm_id: u32,
}

pub enum UserType {
    NU,
    CU,
}

impl HsmConnection {
    pub fn open(token_label: &str, token_pin: &str, user_type: UserType) -> Result<Self, String> {
        let rv = unsafe { p11::C_Initialize(ptr::null_mut()) };
        if rv != p11::CKR_OK {
            return Err(format!("C_Initialize failed with error code: {}", rv));
        }

        let slot_id = Self::find_slot_id(token_label)?;

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

        let user_type = match user_type {
            UserType::NU => p11::CKU_USER,
            UserType::CU => p11::CKU_CRYPTO_USER,
        };
        let rv = unsafe {
            p11::C_Login(
                session,
                user_type,
                token_pin.as_ptr() as *mut u8,
                token_pin.len() as u64,
            )
        };
        if rv != p11::CKR_OK {
            return Err(format!("C_Login failed with error code: {}", rv));
        }

        let fm_slot_id: u64;

        #[cfg(feature = "softhsm")]
        let hsm_connection = {
            fm_slot_id = slot_id;

            Self {
                session,
                fm_slot_id,
            }
        };

        #[cfg(feature = "lunahsm")]
        let hsm_connection = {
            let mut adapter_num: u32 = 0;
            let mut fm_id: u32 = 0;
            let mut embedded_slot_num: u64 = 0;

            let rv = md::initialize(
                slot_id,
                &mut adapter_num,
                &mut embedded_slot_num,
                FM_NAME,
                &mut fm_id,
            );

            fm_slot_id = embedded_slot_num;

            Self {
                session,
                fm_slot_id,
                adapter_num,
                fm_id,
            }
        };

        Ok(hsm_connection)
    }

    // rocket does not have a shutdown hook, so we have to ingnore this method
    #[allow(dead_code)]
    pub fn close(&self) -> Result<(), String> {
        let rv = unsafe { p11::C_Logout(self.session) };
        if rv != p11::CKR_OK {
            return Err(format!("C_Logout failed with error code: {}", rv));
        }

        let rv = unsafe { p11::C_CloseSession(self.session) };
        if rv != p11::CKR_OK {
            return Err(format!("C_CloseSession failed with error code: {}", rv));
        }

        #[cfg(feature = "lunahsm")]
        md::finalize();

        let rv = unsafe { p11::C_Finalize(ptr::null_mut()) };
        if rv != p11::CKR_OK {
            return Err(format!("C_Finalize failed with error code: {}", rv));
        }

        Ok(())
    }

    pub fn send(&self, serialized_request: Vec<u8>) -> Result<String, String> {
        let mut serialized_request = serialized_request;

        // Prepend fm_slot_id bytes to the beginning of serialized_request
        serialized_request.splice(0..0, self.fm_slot_id.to_be_bytes().iter().cloned());

        // Send this serialized data to the HSM
        if serialized_request.len() > FM_MAX_BUFFER_SIZE {
            return Err(format!(
                "HSM buffer size limit is {} but serialized request size is {}",
                FM_MAX_BUFFER_SIZE,
                serialized_request.len()
            ));
        }

        let mut out_buf: [u8; FM_MAX_BUFFER_SIZE] = [0; FM_MAX_BUFFER_SIZE];
        let mut out_len: u32 = 0;

        #[cfg(feature = "softhsm")]
        let _rv = vault_core::handler(
            serialized_request.as_mut_ptr(),
            serialized_request.len() as u32,
            out_buf.as_mut_ptr(),
            &mut out_len,
        );

        #[cfg(feature = "lunahsm")]
        md::send(
            serialized_request.as_mut_ptr(),
            serialized_request.len() as u32,
            out_buf.as_mut_ptr(),
            &mut out_len,
            self.adapter_num,
            self.fm_id,
        );

        if out_len as usize > FM_MAX_BUFFER_SIZE {
            return Err(format!(
                "HSM buffer size limit is {} but serialized response size is {}",
                FM_MAX_BUFFER_SIZE, out_len
            ));
        }

        let out_buf_slice = unsafe { slice::from_raw_parts(out_buf.as_ptr(), out_len as usize) };
        let serialized_response = out_buf_slice.to_vec();

        // Deserialize the response bytes to JSON
        match String::from_utf8(serialized_response) {
            Ok(serialized_response_str) => Ok(serialized_response_str),
            Err(_) => Err("Invalid UTF-8 response".to_string()),
        }
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
}
