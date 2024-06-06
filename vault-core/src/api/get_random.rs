use super::*;

pub fn get_random(session: p11::CK_SESSION_HANDLE, size: u8) -> Result<String, String> {
    let mut random_data = vec![0; size as usize];
    let rv = unsafe {
        p11::C_GenerateRandom(
            session,
            random_data.as_mut_ptr(),
            random_data.len() as c_ulong,
        )
    };

    if rv != p11::CKR_OK {
        return Err(format!("C_GenerateRandom failed with error code: {}", rv));
    }

    let random_data_str = hex::encode(random_data);

    Ok(random_data_str)
}

#[test]
fn test_get_random() {
    let session = shared::test_hsm::init().unwrap();

    let size = 8;
    let result = get_random(session, size);
    assert!(result.is_ok());
    let random_data = hex::decode(result.unwrap()).unwrap();
    assert_eq!(random_data.len(), size as usize);
}
