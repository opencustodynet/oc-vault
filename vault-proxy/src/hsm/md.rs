#![allow(non_snake_case)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct MD_Buffer_t {
    pub pData: *mut u8,
    pub length: u32,
}

impl MD_Buffer_t {
    fn new() -> MD_Buffer_t {
        MD_Buffer_t {
            pData: std::ptr::null_mut(),
            length: 0,
        }
    }
}

extern "C" {
    fn MD_Initialize() -> u32;

    fn MD_GetHsmIndexForSlot(hostP11SlotId: u64, pHsmIndex: *mut u32) -> u32;

    fn MD_GetEmbeddedSlotID(hostP11SlotId: u64, pEmbeddedP11SlotId: *mut u64) -> u32;

    fn MD_GetFmIdFromName(hsmIndex: u32, pName: *const u8, len: u32, fmid: *mut u32) -> u32;

    fn MD_SendReceive(
        hsmIndex: u32,
        originatorId: u32,
        fmNumber: u16,
        pReq: *mut MD_Buffer_t,
        msTimeOut: u32,
        pResp: *mut MD_Buffer_t,
        pReceivedLen: *mut u32,
        pFmStatus: *mut u32,
    ) -> u32;

    fn MD_Finalize();
}

pub fn initialize(
    p11SlotNum: u64,           // IN
    adapterNum: *mut u32,      // OUT
    embeddedSlotNum: *mut u64, // OUT
    fm_name: &str,             // IN
    fmid: *mut u32,            // OUT
) -> u32 {
    let mut rv: u32;

    unsafe {
        rv = MD_Initialize();

        if rv != 0 {
            println!("Error: MD_Initialize failed with {}", rv);
            return rv;
        }

        rv = MD_GetHsmIndexForSlot(p11SlotNum, adapterNum);
        if rv != 0 {
            println!("Error: MD_GetEmbeddedSlotID returned {}", rv);
            MD_Finalize();
            return rv;
        }

        rv = MD_GetEmbeddedSlotID(p11SlotNum, embeddedSlotNum);
        if rv != 0 {
            println!("Error: MD_GetEmbeddedSlotID returned {}", rv);
            MD_Finalize();
            return rv;
        }

        rv = MD_GetFmIdFromName(*adapterNum, fm_name.as_ptr(), fm_name.len() as u32, fmid);
        if rv != 0 {
            println!("Error: MD_GetFmIdFromName returned {}", rv);
            MD_Finalize();
            return rv;
        }
    }

    return rv;
}

pub fn finalize() {
    unsafe {
        MD_Finalize();
    }
}

pub fn send(
    in_buf: *mut u8,
    in_len: u32,
    out_buf: *mut u8,
    out_len: &mut u32,
    adapter_num: u32,
    fm_id: u32,
) -> u32 {
    let mut request = [MD_Buffer_t::new(); 2];
    let mut response = [MD_Buffer_t::new(); 2];

    let mut recv_len: u32 = 0;
    let mut fm_status: u32 = 0;

    request[0].pData = in_buf;
    request[0].length = in_len;
    request[1].pData = std::ptr::null_mut();
    request[1].length = 0;

    response[0].pData = out_buf;
    response[0].length = *out_len;
    response[1].pData = std::ptr::null_mut();
    response[1].length = 0;

    let rv = unsafe {
        MD_SendReceive(
            adapter_num,
            0,
            fm_id as u16,
            request.as_mut_ptr(),
            10000,
            response.as_mut_ptr(),
            &mut recv_len,
            &mut fm_status,
        )
    };
    if rv != 0 || fm_status != 0 {
        println!("FAILED with rv = {}, fm_status = {}", rv, fm_status);
        return if rv != 0 { rv } else { fm_status };
    } else {
        *out_len = recv_len;
    }
    return rv;
}
