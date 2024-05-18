#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
use core::ffi::*;
use core::mem::MaybeUninit;
use core::option::Option;
use core::ptr::*;

pub type CK_FLAGS = c_ulong;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_VERSION {
    pub major: c_uchar,
    pub minor: c_uchar,
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_INFO {
    pub cryptokiVersion: CK_VERSION,
    pub manufacturerID: [c_uchar; 32usize],
    pub flags: CK_FLAGS,
    pub libraryDescription: [c_uchar; 32usize],
    pub libraryVersion: CK_VERSION,
}
pub type CK_NOTIFICATION = c_ulong;
pub type CK_SLOT_ID = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_SLOT_INFO {
    pub slotDescription: [c_uchar; 64usize],
    pub manufacturerID: [c_uchar; 32usize],
    pub flags: CK_FLAGS,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
}
impl Default for CK_SLOT_INFO {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_TOKEN_INFO {
    pub label: [c_uchar; 32usize],
    pub manufacturerID: [c_uchar; 32usize],
    pub model: [c_uchar; 16usize],
    pub serialNumber: [c_uchar; 16usize],
    pub flags: CK_FLAGS,
    pub ulMaxSessionCount: c_ulong,
    pub ulSessionCount: c_ulong,
    pub ulMaxRwSessionCount: c_ulong,
    pub ulRwSessionCount: c_ulong,
    pub ulMaxPinLen: c_ulong,
    pub ulMinPinLen: c_ulong,
    pub ulTotalPublicMemory: c_ulong,
    pub ulFreePublicMemory: c_ulong,
    pub ulTotalPrivateMemory: c_ulong,
    pub ulFreePrivateMemory: c_ulong,
    pub hardwareVersion: CK_VERSION,
    pub firmwareVersion: CK_VERSION,
    pub utcTime: [c_uchar; 16usize],
}
pub type CK_SESSION_HANDLE = c_ulong;
pub type CK_USER_TYPE = c_ulong;
pub type CK_STATE = c_ulong;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
    pub ulDeviceError: c_ulong,
}
pub type CK_OBJECT_HANDLE = c_ulong;
pub type CK_OBJECT_CLASS = c_ulong;
pub type CK_HW_FEATURE_TYPE = c_ulong;
pub type CK_KEY_TYPE = c_ulong;
pub type CK_CERTIFICATE_TYPE = c_ulong;
pub type CK_BIP32_GENERATION_TYPE = c_ulong;
pub type CK_BIP44_GENERATION_TYPE = c_ulong;
pub type CK_ATTRIBUTE_TYPE = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_ATTRIBUTE {
    pub type_: CK_ATTRIBUTE_TYPE,
    pub pValue: *mut c_void,
    pub ulValueLen: c_ulong,
}
impl Default for CK_ATTRIBUTE {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_DATE {
    pub year: [c_uchar; 4usize],
    pub month: [c_uchar; 2usize],
    pub day: [c_uchar; 2usize],
}
pub type CK_MECHANISM_TYPE = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: *mut c_void,
    pub ulParameterLen: c_ulong,
}
impl Default for CK_MECHANISM {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: c_ulong,
    pub ulMaxKeySize: c_ulong,
    pub flags: CK_FLAGS,
}
pub type CK_PARAM_TYPE = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_OTP_PARAM {
    pub type_: CK_PARAM_TYPE,
    pub pValue: *mut c_void,
    pub ulValueLen: c_ulong,
}
impl Default for CK_OTP_PARAM {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_OTP_PARAMS {
    pub pParams: *mut CK_OTP_PARAM,
    pub ulCount: c_ulong,
}
impl Default for CK_OTP_PARAMS {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_OTP_SIGNATURE_INFO {
    pub pParams: *mut CK_OTP_PARAM,
    pub ulCount: c_ulong,
}
impl Default for CK_OTP_SIGNATURE_INFO {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
pub type CK_RSA_PKCS_MGF_TYPE = c_ulong;
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ck_rsa_pkcs_pss_params {
    pub hashAlg: CK_MECHANISM_TYPE,
    pub mgf: CK_RSA_PKCS_MGF_TYPE,
    pub sLen: c_ulong,
}
pub type CK_RSA_PKCS_OAEP_SOURCE_TYPE = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_rsa_pkcs_oaep_params {
    pub hashAlg: CK_MECHANISM_TYPE,
    pub mgf: CK_RSA_PKCS_MGF_TYPE,
    pub source: CK_RSA_PKCS_OAEP_SOURCE_TYPE,
    pub pSourceData: *mut c_void,
    pub ulSourceDataLen: c_ulong,
}
impl Default for ck_rsa_pkcs_oaep_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct ck_aes_ctr_params {
    pub ulCounterBits: c_ulong,
    pub cb: [c_uchar; 16usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_gcm_params {
    pub pIv: *mut c_uchar,
    pub ulIvLen: c_ulong,
    pub ulIvBits: c_ulong,
    pub pAAD: *mut c_uchar,
    pub ulAADLen: c_ulong,
    pub ulTagBits: c_ulong,
}
impl Default for ck_gcm_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
pub type ck_ec_kdf_t = c_ulong;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_ecdh1_derive_params {
    pub kdf: ck_ec_kdf_t,
    pub ulSharedDataLen: c_ulong,
    pub pSharedData: *mut c_uchar,
    pub ulPublicDataLen: c_ulong,
    pub pPublicData: *mut c_uchar,
}
impl Default for ck_ecdh1_derive_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_key_derivation_string_data {
    pub pData: *mut c_uchar,
    pub ulLen: c_ulong,
}
impl Default for ck_key_derivation_string_data {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_des_cbc_encrypt_data_params {
    pub iv: [c_uchar; 8usize],
    pub pData: *mut c_uchar,
    pub length: c_ulong,
}
impl Default for ck_des_cbc_encrypt_data_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_aes_cbc_encrypt_data_params {
    pub iv: [c_uchar; 16usize],
    pub pData: *mut c_uchar,
    pub length: c_ulong,
}
impl Default for ck_aes_cbc_encrypt_data_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_bip32_master_derive_params {
    pub pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    pub ulPublicKeyAttributeCount: c_ulong,
    pub pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    pub ulPrivateKeyAttributeCount: c_ulong,
    pub hPublicKey: CK_OBJECT_HANDLE,
    pub hPrivateKey: CK_OBJECT_HANDLE,
}

impl Default for ck_bip32_master_derive_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

// Thales Luna Bip32 vendor extension functions
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_bip32_child_derive_params {
    pub pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    pub ulPublicKeyAttributeCount: c_ulong,
    pub pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    pub ulPrivateKeyAttributeCount: c_ulong,
    pub pulPath: *mut c_ulong,
    pub ulPathLen: c_ulong,
    pub hPublicKey: CK_OBJECT_HANDLE,
    pub hPrivateKey: CK_OBJECT_HANDLE,
    pub ulPathErrorIndex: c_ulong,
}

// Thales Luna Bip32 vendor extension functions
impl Default for ck_bip32_child_derive_params {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub type CK_RV = c_ulong;
pub type CK_NOTIFY = Option<
    unsafe extern "C" fn(
        session: CK_SESSION_HANDLE,
        event: CK_NOTIFICATION,
        application: *mut c_void,
    ) -> CK_RV,
>;
extern "C" {
    pub fn C_Initialize(init_args: *mut c_void) -> CK_RV;
    pub fn C_Finalize(pReserved: *mut c_void) -> CK_RV;
    pub fn C_GetInfo(info: *mut CK_INFO) -> CK_RV;
    pub fn C_GetSlotList(
        token_present: c_uchar,
        slot_list: *mut CK_SLOT_ID,
        ulCount: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_GetSlotInfo(slotID: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> CK_RV;
    pub fn C_GetTokenInfo(slotID: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> CK_RV;
    pub fn C_WaitForSlotEvent(
        flags: CK_FLAGS,
        slot: *mut CK_SLOT_ID,
        pReserved: *mut c_void,
    ) -> CK_RV;
    pub fn C_GetMechanismList(
        slotID: CK_SLOT_ID,
        mechanism_list: *mut CK_MECHANISM_TYPE,
        ulCount: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_GetMechanismInfo(
        slotID: CK_SLOT_ID,
        type_: CK_MECHANISM_TYPE,
        info: *mut CK_MECHANISM_INFO,
    ) -> CK_RV;
    pub fn C_InitToken(
        slotID: CK_SLOT_ID,
        pin: *mut c_uchar,
        pin_len: c_ulong,
        label: *mut c_uchar,
    ) -> CK_RV;
    pub fn C_InitPIN(session: CK_SESSION_HANDLE, pin: *mut c_uchar, pin_len: c_ulong) -> CK_RV;
    pub fn C_SetPIN(
        session: CK_SESSION_HANDLE,
        old_pin: *mut c_uchar,
        old_len: c_ulong,
        new_pin: *mut c_uchar,
        new_len: c_ulong,
    ) -> CK_RV;
    pub fn C_OpenSession(
        slotID: CK_SLOT_ID,
        flags: CK_FLAGS,
        application: *mut c_void,
        notify: CK_NOTIFY,
        session: *mut CK_SESSION_HANDLE,
    ) -> CK_RV;
    pub fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV;
    pub fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV;
    pub fn C_GetSessionInfo(session: CK_SESSION_HANDLE, info: *mut CK_SESSION_INFO) -> CK_RV;
    pub fn C_GetOperationState(
        session: CK_SESSION_HANDLE,
        operation_state: *mut c_uchar,
        operation_state_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_SetOperationState(
        session: CK_SESSION_HANDLE,
        operation_state: *mut c_uchar,
        operation_state_len: c_ulong,
        encryption_key: CK_OBJECT_HANDLE,
        authentiation_key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_Login(
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: *mut c_uchar,
        pin_len: c_ulong,
    ) -> CK_RV;
    pub fn C_Logout(session: CK_SESSION_HANDLE) -> CK_RV;
    pub fn C_CreateObject(
        session: CK_SESSION_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
        object: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_CopyObject(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
        new_object: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_DestroyObject(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> CK_RV;
    pub fn C_GetObjectSize(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        size: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_GetAttributeValue(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
    ) -> CK_RV;
    pub fn C_SetAttributeValue(
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
    ) -> CK_RV;
    pub fn C_FindObjectsInit(
        session: CK_SESSION_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
    ) -> CK_RV;
    pub fn C_FindObjects(
        session: CK_SESSION_HANDLE,
        object: *mut CK_OBJECT_HANDLE,
        max_object_count: c_ulong,
        object_count: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_FindObjectsFinal(session: CK_SESSION_HANDLE) -> CK_RV;
    pub fn C_EncryptInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_Encrypt(
        session: CK_SESSION_HANDLE,
        data: *mut c_uchar,
        data_len: c_ulong,
        encrypted_data: *mut c_uchar,
        encrypted_data_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_EncryptUpdate(
        session: CK_SESSION_HANDLE,
        part: *mut c_uchar,
        part_len: c_ulong,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_EncryptFinal(
        session: CK_SESSION_HANDLE,
        last_encrypted_part: *mut c_uchar,
        last_encrypted_part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DecryptInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_Decrypt(
        session: CK_SESSION_HANDLE,
        encrypted_data: *mut c_uchar,
        encrypted_data_len: c_ulong,
        data: *mut c_uchar,
        data_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DecryptUpdate(
        session: CK_SESSION_HANDLE,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: c_ulong,
        part: *mut c_uchar,
        part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DecryptFinal(
        session: CK_SESSION_HANDLE,
        last_part: *mut c_uchar,
        last_part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DigestInit(session: CK_SESSION_HANDLE, mechanism: *mut CK_MECHANISM) -> CK_RV;
    pub fn C_Digest(
        session: CK_SESSION_HANDLE,
        data: *mut c_uchar,
        data_len: c_ulong,
        digest: *mut c_uchar,
        digest_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DigestUpdate(
        session: CK_SESSION_HANDLE,
        part: *mut c_uchar,
        part_len: c_ulong,
    ) -> CK_RV;
    pub fn C_DigestKey(session: CK_SESSION_HANDLE, key: CK_OBJECT_HANDLE) -> CK_RV;
    pub fn C_DigestFinal(
        session: CK_SESSION_HANDLE,
        digest: *mut c_uchar,
        digest_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_SignInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_Sign(
        session: CK_SESSION_HANDLE,
        data: *mut c_uchar,
        data_len: c_ulong,
        signature: *mut c_uchar,
        signature_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_SignUpdate(session: CK_SESSION_HANDLE, part: *mut c_uchar, part_len: c_ulong)
        -> CK_RV;
    pub fn C_SignFinal(
        session: CK_SESSION_HANDLE,
        signature: *mut c_uchar,
        signature_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_SignRecoverInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_SignRecover(
        session: CK_SESSION_HANDLE,
        data: *mut c_uchar,
        data_len: c_ulong,
        signature: *mut c_uchar,
        signature_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_VerifyInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_Verify(
        session: CK_SESSION_HANDLE,
        data: *mut c_uchar,
        data_len: c_ulong,
        signature: *mut c_uchar,
        signature_len: c_ulong,
    ) -> CK_RV;
    pub fn C_VerifyUpdate(
        session: CK_SESSION_HANDLE,
        part: *mut c_uchar,
        part_len: c_ulong,
    ) -> CK_RV;
    pub fn C_VerifyFinal(
        session: CK_SESSION_HANDLE,
        signature: *mut c_uchar,
        signature_len: c_ulong,
    ) -> CK_RV;
    pub fn C_VerifyRecoverInit(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_VerifyRecover(
        session: CK_SESSION_HANDLE,
        signature: *mut c_uchar,
        signature_len: c_ulong,
        data: *mut c_uchar,
        data_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DigestEncryptUpdate(
        session: CK_SESSION_HANDLE,
        part: *mut c_uchar,
        part_len: c_ulong,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DecryptDigestUpdate(
        session: CK_SESSION_HANDLE,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: c_ulong,
        part: *mut c_uchar,
        part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_SignEncryptUpdate(
        session: CK_SESSION_HANDLE,
        part: *mut c_uchar,
        part_len: c_ulong,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_DecryptVerifyUpdate(
        session: CK_SESSION_HANDLE,
        encrypted_part: *mut c_uchar,
        encrypted_part_len: c_ulong,
        part: *mut c_uchar,
        part_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_GenerateKey(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        templ: *mut CK_ATTRIBUTE,
        ulCount: c_ulong,
        key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_GenerateKeyPair(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        public_key_template: *mut CK_ATTRIBUTE,
        public_key_attribute_count: c_ulong,
        private_key_template: *mut CK_ATTRIBUTE,
        private_key_attribute_count: c_ulong,
        public_key: *mut CK_OBJECT_HANDLE,
        private_key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_WrapKey(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        wrapping_key: CK_OBJECT_HANDLE,
        key: CK_OBJECT_HANDLE,
        wrapped_key: *mut c_uchar,
        wrapped_key_len: *mut c_ulong,
    ) -> CK_RV;
    pub fn C_UnwrapKey(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        unwrapping_key: CK_OBJECT_HANDLE,
        wrapped_key: *mut c_uchar,
        wrapped_key_len: c_ulong,
        templ: *mut CK_ATTRIBUTE,
        attribute_count: c_ulong,
        key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_DeriveKey(
        session: CK_SESSION_HANDLE,
        mechanism: *mut CK_MECHANISM,
        base_key: CK_OBJECT_HANDLE,
        templ: *mut CK_ATTRIBUTE,
        attribute_count: c_ulong,
        key: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV;
    pub fn C_SeedRandom(session: CK_SESSION_HANDLE, seed: *mut c_uchar, seed_len: c_ulong)
        -> CK_RV;
    pub fn C_GenerateRandom(
        session: CK_SESSION_HANDLE,
        random_data: *mut c_uchar,
        random_len: c_ulong,
    ) -> CK_RV;
    pub fn C_GetFunctionStatus(session: CK_SESSION_HANDLE) -> CK_RV;
    pub fn C_CancelFunction(session: CK_SESSION_HANDLE) -> CK_RV;
}
pub type CK_CREATEMUTEX = Option<unsafe extern "C" fn(mutex: *mut *mut c_void) -> CK_RV>;
pub type CK_DESTROYMUTEX = Option<unsafe extern "C" fn(mutex: *mut c_void) -> CK_RV>;
pub type CK_LOCKMUTEX = Option<unsafe extern "C" fn(mutex: *mut c_void) -> CK_RV>;
pub type CK_UNLOCKMUTEX = Option<unsafe extern "C" fn(mutex: *mut c_void) -> CK_RV>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CK_C_INITIALIZE_ARGS {
    pub CreateMutex: CK_CREATEMUTEX,
    pub DestroyMutex: CK_DESTROYMUTEX,
    pub LockMutex: CK_LOCKMUTEX,
    pub UnlockMutex: CK_UNLOCKMUTEX,
    pub flags: CK_FLAGS,
    pub pReserved: *mut c_void,
}
impl Default for CK_C_INITIALIZE_ARGS {
    fn default() -> Self {
        let mut s = MaybeUninit::<Self>::uninit();
        unsafe {
            write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
pub type size_t = c_ulong;
pub type wchar_t = c_int;
pub type CK_BYTE = c_uchar;
pub type CK_CHAR = c_uchar;
pub type CK_UTF8CHAR = c_uchar;
pub type CK_BBOOL = c_uchar;
pub type CK_ULONG = c_ulong;
pub type CK_LONG = c_long;
pub type CK_BYTE_PTR = *mut CK_BYTE;
pub type CK_CHAR_PTR = *mut CK_CHAR;
pub type CK_UTF8CHAR_PTR = *mut CK_UTF8CHAR;
pub type CK_ULONG_PTR = *mut CK_ULONG;
pub type CK_VOID_PTR = *mut c_void;
pub type CK_VOID_PTR_PTR = *mut *mut c_void;
pub type CK_VERSION_PTR = *mut CK_VERSION;
pub type CK_INFO_PTR = *mut CK_INFO;
pub type CK_SLOT_ID_PTR = *mut CK_SLOT_ID;
pub type CK_SLOT_INFO_PTR = *mut CK_SLOT_INFO;
pub type CK_TOKEN_INFO_PTR = *mut CK_TOKEN_INFO;
pub type CK_SESSION_HANDLE_PTR = *mut CK_SESSION_HANDLE;
pub type CK_SESSION_INFO_PTR = *mut CK_SESSION_INFO;
pub type CK_OBJECT_HANDLE_PTR = *mut CK_OBJECT_HANDLE;
pub type CK_OBJECT_CLASS_PTR = *mut CK_OBJECT_CLASS;
pub type CK_ATTRIBUTE_PTR = *mut CK_ATTRIBUTE;
pub type CK_DATE_PTR = *mut CK_DATE;
pub type CK_MECHANISM_TYPE_PTR = *mut CK_MECHANISM_TYPE;
pub type CK_MECHANISM_PTR = *mut CK_MECHANISM;
pub type CK_MECHANISM_INFO_PTR = *mut CK_MECHANISM_INFO;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ck_otp_mechanism_info {
    _unused: [u8; 0],
}
pub type CK_OTP_MECHANISM_INFO = ck_otp_mechanism_info;
pub type CK_OTP_MECHANISM_INFO_PTR = *mut ck_otp_mechanism_info;
pub type CK_C_INITIALIZE_ARGS_PTR = *mut CK_C_INITIALIZE_ARGS;
pub type CK_RSA_PKCS_PSS_PARAMS = ck_rsa_pkcs_pss_params;
pub type CK_RSA_PKCS_PSS_PARAMS_PTR = *mut ck_rsa_pkcs_pss_params;
pub type CK_RSA_PKCS_OAEP_PARAMS = ck_rsa_pkcs_oaep_params;
pub type CK_RSA_PKCS_OAEP_PARAMS_PTR = *mut ck_rsa_pkcs_oaep_params;
pub type CK_AES_CTR_PARAMS = ck_aes_ctr_params;
pub type CK_AES_CTR_PARAMS_PTR = *mut ck_aes_ctr_params;
pub type CK_GCM_PARAMS = ck_gcm_params;
pub type CK_GCM_PARAMS_PTR = *mut ck_gcm_params;
pub type CK_ECDH1_DERIVE_PARAMS = ck_ecdh1_derive_params;
pub type CK_ECDH1_DERIVE_PARAMS_PTR = *mut ck_ecdh1_derive_params;
pub type CK_KEY_DERIVATION_STRING_DATA = ck_key_derivation_string_data;
pub type CK_KEY_DERIVATION_STRING_DATA_PTR = *mut ck_key_derivation_string_data;
pub type CK_DES_CBC_ENCRYPT_DATA_PARAMS = ck_des_cbc_encrypt_data_params;
pub type CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR = *mut ck_des_cbc_encrypt_data_params;
pub type CK_AES_CBC_ENCRYPT_DATA_PARAMS = ck_aes_cbc_encrypt_data_params;
pub type CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR = *mut ck_aes_cbc_encrypt_data_params;
pub type CK_BIP32_MASTER_DERIVE_PARAMS = ck_bip32_master_derive_params;
pub type CK_BIP32_MASTER_DERIVE_PARAMS_PTR = *mut ck_bip32_master_derive_params;
pub type CK_BIP32_CHILD_DERIVE_PARAMS = ck_bip32_child_derive_params;
pub type CK_BIP32_CHILD_DERIVE_PARAMS_PTR = *mut ck_bip32_child_derive_params;
pub const CKU_SO: CK_USER_TYPE = 0;
pub const CKU_USER: CK_USER_TYPE = 1;
pub const CKU_CRYPTO_USER: CK_USER_TYPE = 0x80000001;
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

// CUSTOM ADDED CONSTANTS

/// Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
/// CKM_X9_42_DH_PARAMETER_GEN mechanisms
pub type CK_X9_42_DH_KDF_TYPE = CK_ULONG;
pub type CK_X9_42_DH_KDF_TYPE_PTR = *mut CK_X9_42_DH_KDF_TYPE;

pub type CK_EC_KDF_TYPE = CK_ULONG;

// The values below are defined in pkcs11.h with `#define` macros. As a result, bindgen cannot
// generate bindings for them. They are included here for completeness.
pub const CKN_SURRENDER: CK_NOTIFICATION = 0;
pub const CKF_TOKEN_PRESENT: CK_FLAGS = 0x00000001;
pub const CKF_REMOVABLE_DEVICE: CK_FLAGS = 0x00000002;
pub const CKF_HW_SLOT: CK_FLAGS = 0x00000004;
pub const CKF_ARRAY_ATTRIBUTE: CK_FLAGS = 0x40000000;
pub const CKA_WRAP_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000211;
pub const CKA_UNWRAP_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000212;
pub const CKA_DERIVE_TEMPLATE: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000213;
pub const CKA_ALLOWED_MECHANISMS: CK_ATTRIBUTE_TYPE = CKF_ARRAY_ATTRIBUTE | 0x00000600;
pub const CKF_RNG: CK_FLAGS = 0x00000001;
pub const CKF_WRITE_PROTECTED: CK_FLAGS = 0x00000002;
pub const CKF_LOGIN_REQUIRED: CK_FLAGS = 0x00000004;
pub const CKF_USER_PIN_INITIALIZED: CK_FLAGS = 0x00000008;
pub const CKF_RESTORE_KEY_NOT_NEEDED: CK_FLAGS = 0x00000020;
pub const CKF_CLOCK_ON_TOKEN: CK_FLAGS = 0x00000040;
pub const CKF_PROTECTED_AUTHENTICATION_PATH: CK_FLAGS = 0x00000100;
pub const CKF_DUAL_CRYPTO_OPERATIONS: CK_FLAGS = 0x00000200;
pub const CKF_TOKEN_INITIALIZED: CK_FLAGS = 0x00000400;
pub const CKF_SECONDARY_AUTHENTICATION: CK_FLAGS = 0x00000800;
pub const CKF_USER_PIN_COUNT_LOW: CK_FLAGS = 0x00010000;
pub const CKF_USER_PIN_FINAL_TRY: CK_FLAGS = 0x00020000;
pub const CKF_USER_PIN_LOCKED: CK_FLAGS = 0x00040000;
pub const CKF_USER_PIN_TO_BE_CHANGED: CK_FLAGS = 0x00080000;
pub const CKF_SO_PIN_COUNT_LOW: CK_FLAGS = 0x00100000;
pub const CKF_SO_PIN_FINAL_TRY: CK_FLAGS = 0x00200000;
pub const CKF_SO_PIN_LOCKED: CK_FLAGS = 0x00400000;
pub const CKF_SO_PIN_TO_BE_CHANGED: CK_FLAGS = 0x00800000;
pub const CKF_ERROR_STATE: CK_FLAGS = 0x01000000;
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG = !0;
pub const CK_EFFECTIVELY_INFINITE: CK_ULONG = 0;
pub const CK_INVALID_HANDLE: CK_ULONG = 0;
pub const CKS_RO_PUBLIC_SESSION: CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS: CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION: CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS: CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS: CK_STATE = 4;
pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;
pub const CKO_DATA: CK_OBJECT_CLASS = 0x00000000;
pub const CKO_CERTIFICATE: CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY: CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY: CK_OBJECT_CLASS = 0x00000003;
pub const CKO_SECRET_KEY: CK_OBJECT_CLASS = 0x00000004;
pub const CKO_HW_FEATURE: CK_OBJECT_CLASS = 0x00000005;
pub const CKO_DOMAIN_PARAMETERS: CK_OBJECT_CLASS = 0x00000006;
pub const CKO_MECHANISM: CK_OBJECT_CLASS = 0x00000007;
pub const CKO_OTP_KEY: CK_OBJECT_CLASS = 0x00000008;
pub const CKO_VENDOR_DEFINED: CK_OBJECT_CLASS = 0x80000000;
pub const CKH_MONOTONIC_COUNTER: CK_HW_FEATURE_TYPE = 0x00000001;
pub const CKH_CLOCK: CK_HW_FEATURE_TYPE = 0x00000002;
pub const CKH_USER_INTERFACE: CK_HW_FEATURE_TYPE = 0x00000003;
pub const CKH_VENDOR_DEFINED: CK_HW_FEATURE_TYPE = 0x80000000;
pub const CKK_RSA: CK_KEY_TYPE = 0x00000000;
pub const CKK_DSA: CK_KEY_TYPE = 0x00000001;
pub const CKK_DH: CK_KEY_TYPE = 0x00000002;
pub const CKK_ECDSA: CK_KEY_TYPE = CKK_EC;
pub const CKK_EC: CK_KEY_TYPE = 0x00000003;
pub const CKK_X9_42_DH: CK_KEY_TYPE = 0x00000004;
pub const CKK_KEA: CK_KEY_TYPE = 0x00000005;
pub const CKK_GENERIC_SECRET: CK_KEY_TYPE = 0x00000010;
pub const CKK_RC2: CK_KEY_TYPE = 0x00000011;
pub const CKK_RC4: CK_KEY_TYPE = 0x00000012;
pub const CKK_DES: CK_KEY_TYPE = 0x00000013;
pub const CKK_DES2: CK_KEY_TYPE = 0x00000014;
pub const CKK_DES3: CK_KEY_TYPE = 0x00000015;
pub const CKK_CAST: CK_KEY_TYPE = 0x00000016;
pub const CKK_CAST3: CK_KEY_TYPE = 0x00000017;
pub const CKK_CAST5: CK_KEY_TYPE = CKK_CAST128;
pub const CKK_CAST128: CK_KEY_TYPE = 0x00000018;
pub const CKK_RC5: CK_KEY_TYPE = 0x00000019;
pub const CKK_IDEA: CK_KEY_TYPE = 0x0000001A;
pub const CKK_SKIPJACK: CK_KEY_TYPE = 0x0000001B;
pub const CKK_BATON: CK_KEY_TYPE = 0x0000001C;
pub const CKK_JUNIPER: CK_KEY_TYPE = 0x0000001D;
pub const CKK_CDMF: CK_KEY_TYPE = 0x0000001E;
pub const CKK_AES: CK_KEY_TYPE = 0x0000001F;
pub const CKK_BLOWFISH: CK_KEY_TYPE = 0x00000020;
pub const CKK_TWOFISH: CK_KEY_TYPE = 0x00000021;
pub const CKK_SECURID: CK_KEY_TYPE = 0x00000022;
pub const CKK_HOTP: CK_KEY_TYPE = 0x00000023;
pub const CKK_ACTI: CK_KEY_TYPE = 0x00000024;
pub const CKK_CAMELLIA: CK_KEY_TYPE = 0x00000025;
pub const CKK_ARIA: CK_KEY_TYPE = 0x00000026;
pub const CKK_MD5_HMAC: CK_KEY_TYPE = 0x00000027;
pub const CKK_SHA_1_HMAC: CK_KEY_TYPE = 0x00000028;
pub const CKK_RIPEMD128_HMAC: CK_KEY_TYPE = 0x00000029;
pub const CKK_RIPEMD160_HMAC: CK_KEY_TYPE = 0x0000002A;
pub const CKK_SHA256_HMAC: CK_KEY_TYPE = 0x0000002B;
pub const CKK_SHA384_HMAC: CK_KEY_TYPE = 0x0000002C;
pub const CKK_SHA512_HMAC: CK_KEY_TYPE = 0x0000002D;
pub const CKK_SHA224_HMAC: CK_KEY_TYPE = 0x0000002E;
pub const CKK_SEED: CK_KEY_TYPE = 0x0000002F;
pub const CKK_GOSTR3410: CK_KEY_TYPE = 0x00000030;
pub const CKK_GOSTR3411: CK_KEY_TYPE = 0x00000031;
pub const CKK_GOST28147: CK_KEY_TYPE = 0x00000032;
pub const CKK_EC_EDWARDS: CK_KEY_TYPE = 0x00000040;
pub const CKK_EC_MONTGOMERY: CK_KEY_TYPE = 0x00000041;
pub const CKK_VENDOR_DEFINED: CK_KEY_TYPE = 0x80000000;
pub const CKC_X_509: CK_CERTIFICATE_TYPE = 0x00000000;
pub const CKC_X_509_ATTR_CERT: CK_CERTIFICATE_TYPE = 0x00000001;
pub const CKC_WTLS: CK_CERTIFICATE_TYPE = 0x00000002;
pub const CKC_VENDOR_DEFINED: CK_CERTIFICATE_TYPE = 0x80000000;
pub const CKA_CLASS: CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN: CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE: CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL: CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_APPLICATION: CK_ATTRIBUTE_TYPE = 0x00000010;
pub const CKA_VALUE: CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_OBJECT_ID: CK_ATTRIBUTE_TYPE = 0x00000012;
pub const CKA_CERTIFICATE_TYPE: CK_ATTRIBUTE_TYPE = 0x00000080;
pub const CKA_ISSUER: CK_ATTRIBUTE_TYPE = 0x00000081;
pub const CKA_SERIAL_NUMBER: CK_ATTRIBUTE_TYPE = 0x00000082;
pub const CKA_AC_ISSUER: CK_ATTRIBUTE_TYPE = 0x00000083;
pub const CKA_OWNER: CK_ATTRIBUTE_TYPE = 0x00000084;
pub const CKA_ATTR_TYPES: CK_ATTRIBUTE_TYPE = 0x00000085;
pub const CKA_TRUSTED: CK_ATTRIBUTE_TYPE = 0x00000086;
pub const CKA_CERTIFICATE_CATEGORY: CK_ATTRIBUTE_TYPE = 0x00000087;
pub const CKA_JAVA_MIDP_SECURITY_DOMAIN: CK_ATTRIBUTE_TYPE = 0x00000088;
pub const CKA_URL: CK_ATTRIBUTE_TYPE = 0x00000089;
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY: CK_ATTRIBUTE_TYPE = 0x0000008A;
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY: CK_ATTRIBUTE_TYPE = 0x0000008B;
pub const CKA_NAME_HASH_ALGORITHM: CK_ATTRIBUTE_TYPE = 0x0000008C;
pub const CKA_CHECK_VALUE: CK_ATTRIBUTE_TYPE = 0x00000090;
pub const CKA_KEY_TYPE: CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_SUBJECT: CK_ATTRIBUTE_TYPE = 0x00000101;
pub const CKA_ID: CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT: CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT: CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_WRAP: CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP: CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN: CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_SIGN_RECOVER: CK_ATTRIBUTE_TYPE = 0x00000109;
pub const CKA_VERIFY: CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_VERIFY_RECOVER: CK_ATTRIBUTE_TYPE = 0x0000010B;
pub const CKA_DERIVE: CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_START_DATE: CK_ATTRIBUTE_TYPE = 0x00000110;
pub const CKA_END_DATE: CK_ATTRIBUTE_TYPE = 0x00000111;
pub const CKA_MODULUS: CK_ATTRIBUTE_TYPE = 0x00000120;
pub const CKA_MODULUS_BITS: CK_ATTRIBUTE_TYPE = 0x00000121;
pub const CKA_PUBLIC_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000122;
pub const CKA_PRIVATE_EXPONENT: CK_ATTRIBUTE_TYPE = 0x00000123;
pub const CKA_PRIME_1: CK_ATTRIBUTE_TYPE = 0x00000124;
pub const CKA_PRIME_2: CK_ATTRIBUTE_TYPE = 0x00000125;
pub const CKA_EXPONENT_1: CK_ATTRIBUTE_TYPE = 0x00000126;
pub const CKA_EXPONENT_2: CK_ATTRIBUTE_TYPE = 0x00000127;
pub const CKA_COEFFICIENT: CK_ATTRIBUTE_TYPE = 0x00000128;
pub const CKA_PUBLIC_KEY_INFO: CK_ATTRIBUTE_TYPE = 0x00000129;
pub const CKA_PRIME: CK_ATTRIBUTE_TYPE = 0x00000130;
pub const CKA_SUBPRIME: CK_ATTRIBUTE_TYPE = 0x00000131;
pub const CKA_BASE: CK_ATTRIBUTE_TYPE = 0x00000132;
pub const CKA_PRIME_BITS: CK_ATTRIBUTE_TYPE = 0x00000133;
pub const CKA_SUBPRIME_BITS: CK_ATTRIBUTE_TYPE = 0x00000134;
pub const CKA_SUB_PRIME_BITS: CK_ATTRIBUTE_TYPE = CKA_SUBPRIME_BITS;
pub const CKA_VALUE_BITS: CK_ATTRIBUTE_TYPE = 0x00000160;
pub const CKA_VALUE_LEN: CK_ATTRIBUTE_TYPE = 0x00000161;
pub const CKA_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_LOCAL: CK_ATTRIBUTE_TYPE = 0x00000163;
pub const CKA_NEVER_EXTRACTABLE: CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE: CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_KEY_GEN_MECHANISM: CK_ATTRIBUTE_TYPE = 0x00000166;
pub const CKA_MODIFIABLE: CK_ATTRIBUTE_TYPE = 0x00000170;
pub const CKA_COPYABLE: CK_ATTRIBUTE_TYPE = 0x00000171;
pub const CKA_DESTROYABLE: CK_ATTRIBUTE_TYPE = 0x00000172;
pub const CKA_ECDSA_PARAMS: CK_ATTRIBUTE_TYPE = CKA_EC_PARAMS;
pub const CKA_EC_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000180;
pub const CKA_EC_POINT: CK_ATTRIBUTE_TYPE = 0x00000181;
pub const CKA_SECONDARY_AUTH: CK_ATTRIBUTE_TYPE = 0x00000200; /* Deprecated */
pub const CKA_AUTH_PIN_FLAGS: CK_ATTRIBUTE_TYPE = 0x00000201; /* Deprecated */
pub const CKA_ALWAYS_AUTHENTICATE: CK_ATTRIBUTE_TYPE = 0x00000202;
pub const CKA_WRAP_WITH_TRUSTED: CK_ATTRIBUTE_TYPE = 0x00000210;
pub const CKA_OTP_FORMAT: CK_ATTRIBUTE_TYPE = 0x00000220;
pub const CKA_OTP_LENGTH: CK_ATTRIBUTE_TYPE = 0x00000221;
pub const CKA_OTP_TIME_INTERVAL: CK_ATTRIBUTE_TYPE = 0x00000222;
pub const CKA_OTP_USER_FRIENDLY_MODE: CK_ATTRIBUTE_TYPE = 0x00000223;
pub const CKA_OTP_CHALLENGE_REQUIREMENT: CK_ATTRIBUTE_TYPE = 0x00000224;
pub const CKA_OTP_TIME_REQUIREMENT: CK_ATTRIBUTE_TYPE = 0x00000225;
pub const CKA_OTP_COUNTER_REQUIREMENT: CK_ATTRIBUTE_TYPE = 0x00000226;
pub const CKA_OTP_PIN_REQUIREMENT: CK_ATTRIBUTE_TYPE = 0x00000227;
pub const CKA_OTP_USER_IDENTIFIER: CK_ATTRIBUTE_TYPE = 0x0000022A;
pub const CKA_OTP_SERVICE_IDENTIFIER: CK_ATTRIBUTE_TYPE = 0x0000022B;
pub const CKA_OTP_SERVICE_LOGO: CK_ATTRIBUTE_TYPE = 0x0000022C;
pub const CKA_OTP_SERVICE_LOGO_TYPE: CK_ATTRIBUTE_TYPE = 0x0000022D;
pub const CKA_OTP_COUNTER: CK_ATTRIBUTE_TYPE = 0x0000022E;
pub const CKA_OTP_TIME: CK_ATTRIBUTE_TYPE = 0x0000022F;
pub const CKA_GOSTR3410_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000250;
pub const CKA_GOSTR3411_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000251;
pub const CKA_GOST28147_PARAMS: CK_ATTRIBUTE_TYPE = 0x00000252;
pub const CKA_HW_FEATURE_TYPE: CK_ATTRIBUTE_TYPE = 0x00000300;
pub const CKA_RESET_ON_INIT: CK_ATTRIBUTE_TYPE = 0x00000301;
pub const CKA_HAS_RESET: CK_ATTRIBUTE_TYPE = 0x00000302;
pub const CKA_PIXEL_X: CK_ATTRIBUTE_TYPE = 0x00000400;
pub const CKA_PIXEL_Y: CK_ATTRIBUTE_TYPE = 0x00000401;
pub const CKA_RESOLUTION: CK_ATTRIBUTE_TYPE = 0x00000402;
pub const CKA_CHAR_ROWS: CK_ATTRIBUTE_TYPE = 0x00000403;
pub const CKA_CHAR_COLUMNS: CK_ATTRIBUTE_TYPE = 0x00000404;
pub const CKA_COLOR: CK_ATTRIBUTE_TYPE = 0x00000405;
pub const CKA_BITS_PER_PIXEL: CK_ATTRIBUTE_TYPE = 0x00000406;
pub const CKA_CHAR_SETS: CK_ATTRIBUTE_TYPE = 0x00000480;
pub const CKA_ENCODING_METHODS: CK_ATTRIBUTE_TYPE = 0x00000481;
pub const CKA_MIME_TYPES: CK_ATTRIBUTE_TYPE = 0x00000482;
pub const CKA_MECHANISM_TYPE: CK_ATTRIBUTE_TYPE = 0x00000500;
pub const CKA_REQUIRED_CMS_ATTRIBUTES: CK_ATTRIBUTE_TYPE = 0x00000501;
pub const CKA_DEFAULT_CMS_ATTRIBUTES: CK_ATTRIBUTE_TYPE = 0x00000502;
pub const CKA_SUPPORTED_CMS_ATTRIBUTES: CK_ATTRIBUTE_TYPE = 0x00000503;
pub const CKA_VENDOR_DEFINED: CK_ATTRIBUTE_TYPE = 0x80000000;
pub const CKA_BIP32_CHAIN_CODE: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1100;
pub const CKA_BIP32_VERSION_BYTES: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1101;
pub const CKA_BIP32_CHILD_INDEX: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1102;
pub const CKA_BIP32_CHILD_DEPTH: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1103;
pub const CKA_BIP32_ID: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1104;
pub const CKA_BIP32_FINGERPRINT: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1105;
pub const CKA_BIP32_PARENT_FINGERPRINT: CK_ATTRIBUTE_TYPE = CKA_VENDOR_DEFINED + 0x1106;
pub const CKM_RSA_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_9796: CK_MECHANISM_TYPE = 0x00000002;
pub const CKM_RSA_X_509: CK_MECHANISM_TYPE = 0x00000003;
pub const CKM_MD2_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000004;
pub const CKM_MD5_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000005;
pub const CKM_SHA1_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000006;
pub const CKM_RIPEMD128_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000007;
pub const CKM_RIPEMD160_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000008;
pub const CKM_RSA_PKCS_OAEP: CK_MECHANISM_TYPE = 0x00000009;
pub const CKM_RSA_X9_31_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x0000000A;
pub const CKM_RSA_X9_31: CK_MECHANISM_TYPE = 0x0000000B;
pub const CKM_SHA1_RSA_X9_31: CK_MECHANISM_TYPE = 0x0000000C;
pub const CKM_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x0000000D;
pub const CKM_SHA1_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x0000000E;
pub const CKM_DSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000010;
pub const CKM_DSA: CK_MECHANISM_TYPE = 0x00000011;
pub const CKM_DSA_SHA1: CK_MECHANISM_TYPE = 0x00000012;
pub const CKM_DSA_SHA224: CK_MECHANISM_TYPE = 0x00000013;
pub const CKM_DSA_SHA256: CK_MECHANISM_TYPE = 0x00000014;
pub const CKM_DSA_SHA384: CK_MECHANISM_TYPE = 0x00000015;
pub const CKM_DSA_SHA512: CK_MECHANISM_TYPE = 0x00000016;
pub const CKM_DH_PKCS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000020;
pub const CKM_DH_PKCS_DERIVE: CK_MECHANISM_TYPE = 0x00000021;
pub const CKM_X9_42_DH_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00000030;
pub const CKM_X9_42_DH_DERIVE: CK_MECHANISM_TYPE = 0x00000031;
pub const CKM_X9_42_DH_HYBRID_DERIVE: CK_MECHANISM_TYPE = 0x00000032;
pub const CKM_X9_42_MQV_DERIVE: CK_MECHANISM_TYPE = 0x00000033;
pub const CKM_SHA256_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA256_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000043;
pub const CKM_SHA384_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000044;
pub const CKM_SHA512_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000045;
pub const CKM_SHA512_224: CK_MECHANISM_TYPE = 0x00000048;
pub const CKM_SHA512_224_HMAC: CK_MECHANISM_TYPE = 0x00000049;
pub const CKM_SHA512_224_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x0000004A;
pub const CKM_SHA512_224_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x0000004B;
pub const CKM_SHA512_256: CK_MECHANISM_TYPE = 0x0000004C;
pub const CKM_SHA512_256_HMAC: CK_MECHANISM_TYPE = 0x0000004D;
pub const CKM_SHA512_256_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x0000004E;
pub const CKM_SHA512_256_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x0000004F;
pub const CKM_SHA512_T: CK_MECHANISM_TYPE = 0x00000050;
pub const CKM_SHA512_T_HMAC: CK_MECHANISM_TYPE = 0x00000051;
pub const CKM_SHA512_T_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000052;
pub const CKM_SHA512_T_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000053;
pub const CKM_RC2_KEY_GEN: CK_MECHANISM_TYPE = 0x00000100;
pub const CKM_RC2_ECB: CK_MECHANISM_TYPE = 0x00000101;
pub const CKM_RC2_CBC: CK_MECHANISM_TYPE = 0x00000102;
pub const CKM_RC2_MAC: CK_MECHANISM_TYPE = 0x00000103;
pub const CKM_RC2_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000104;
pub const CKM_RC2_CBC_PAD: CK_MECHANISM_TYPE = 0x00000105;
pub const CKM_RC4_KEY_GEN: CK_MECHANISM_TYPE = 0x00000110;
pub const CKM_RC4: CK_MECHANISM_TYPE = 0x00000111;
pub const CKM_DES_KEY_GEN: CK_MECHANISM_TYPE = 0x00000120;
pub const CKM_DES_ECB: CK_MECHANISM_TYPE = 0x00000121;
pub const CKM_DES_CBC: CK_MECHANISM_TYPE = 0x00000122;
pub const CKM_DES_MAC: CK_MECHANISM_TYPE = 0x00000123;
pub const CKM_DES_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000124;
pub const CKM_DES_CBC_PAD: CK_MECHANISM_TYPE = 0x00000125;
pub const CKM_DES2_KEY_GEN: CK_MECHANISM_TYPE = 0x00000130;
pub const CKM_DES3_KEY_GEN: CK_MECHANISM_TYPE = 0x00000131;
pub const CKM_DES3_ECB: CK_MECHANISM_TYPE = 0x00000132;
pub const CKM_DES3_CBC: CK_MECHANISM_TYPE = 0x00000133;
pub const CKM_DES3_MAC: CK_MECHANISM_TYPE = 0x00000134;
pub const CKM_DES3_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000135;
pub const CKM_DES3_CBC_PAD: CK_MECHANISM_TYPE = 0x00000136;
pub const CKM_DES3_CMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000137;
pub const CKM_DES3_CMAC: CK_MECHANISM_TYPE = 0x00000138;
pub const CKM_CDMF_KEY_GEN: CK_MECHANISM_TYPE = 0x00000140;
pub const CKM_CDMF_ECB: CK_MECHANISM_TYPE = 0x00000141;
pub const CKM_CDMF_CBC: CK_MECHANISM_TYPE = 0x00000142;
pub const CKM_CDMF_MAC: CK_MECHANISM_TYPE = 0x00000143;
pub const CKM_CDMF_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000144;
pub const CKM_CDMF_CBC_PAD: CK_MECHANISM_TYPE = 0x00000145;
pub const CKM_DES_OFB64: CK_MECHANISM_TYPE = 0x00000150;
pub const CKM_DES_OFB8: CK_MECHANISM_TYPE = 0x00000151;
pub const CKM_DES_CFB64: CK_MECHANISM_TYPE = 0x00000152;
pub const CKM_DES_CFB8: CK_MECHANISM_TYPE = 0x00000153;
pub const CKM_MD2: CK_MECHANISM_TYPE = 0x00000200;
pub const CKM_MD2_HMAC: CK_MECHANISM_TYPE = 0x00000201;
pub const CKM_MD2_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000202;
pub const CKM_MD5: CK_MECHANISM_TYPE = 0x00000210;
pub const CKM_MD5_HMAC: CK_MECHANISM_TYPE = 0x00000211;
pub const CKM_MD5_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000212;
pub const CKM_SHA_1: CK_MECHANISM_TYPE = 0x00000220;
pub const CKM_SHA_1_HMAC: CK_MECHANISM_TYPE = 0x00000221;
pub const CKM_SHA_1_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000222;
pub const CKM_RIPEMD128: CK_MECHANISM_TYPE = 0x00000230;
pub const CKM_RIPEMD128_HMAC: CK_MECHANISM_TYPE = 0x00000231;
pub const CKM_RIPEMD128_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000232;
pub const CKM_RIPEMD160: CK_MECHANISM_TYPE = 0x00000240;
pub const CKM_RIPEMD160_HMAC: CK_MECHANISM_TYPE = 0x00000241;
pub const CKM_RIPEMD160_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000242;
pub const CKM_SHA256: CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA256_HMAC: CK_MECHANISM_TYPE = 0x00000251;
pub const CKM_SHA256_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000252;
pub const CKM_SHA384: CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA384_HMAC: CK_MECHANISM_TYPE = 0x00000261;
pub const CKM_SHA384_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000262;
pub const CKM_SHA512: CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_SHA512_HMAC: CK_MECHANISM_TYPE = 0x00000271;
pub const CKM_SHA512_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000272;
pub const CKM_SECURID_KEY_GEN: CK_MECHANISM_TYPE = 0x00000280;
pub const CKM_SECURID: CK_MECHANISM_TYPE = 0x00000282;
pub const CKM_HOTP_KEY_GEN: CK_MECHANISM_TYPE = 0x00000290;
pub const CKM_HOTP: CK_MECHANISM_TYPE = 0x00000291;
pub const CKM_ACTI: CK_MECHANISM_TYPE = 0x000002A0;
pub const CKM_ACTI_KEY_GEN: CK_MECHANISM_TYPE = 0x000002A1;
pub const CKM_CAST_KEY_GEN: CK_MECHANISM_TYPE = 0x00000300;
pub const CKM_CAST_ECB: CK_MECHANISM_TYPE = 0x00000301;
pub const CKM_CAST_CBC: CK_MECHANISM_TYPE = 0x00000302;
pub const CKM_CAST_MAC: CK_MECHANISM_TYPE = 0x00000303;
pub const CKM_CAST_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000304;
pub const CKM_CAST_CBC_PAD: CK_MECHANISM_TYPE = 0x00000305;
pub const CKM_CAST3_KEY_GEN: CK_MECHANISM_TYPE = 0x00000310;
pub const CKM_CAST3_ECB: CK_MECHANISM_TYPE = 0x00000311;
pub const CKM_CAST3_CBC: CK_MECHANISM_TYPE = 0x00000312;
pub const CKM_CAST3_MAC: CK_MECHANISM_TYPE = 0x00000313;
pub const CKM_CAST3_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000314;
pub const CKM_CAST3_CBC_PAD: CK_MECHANISM_TYPE = 0x00000315;
pub const CKM_CAST5_KEY_GEN: CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST128_KEY_GEN: CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST5_ECB: CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST128_ECB: CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST5_CBC: CK_MECHANISM_TYPE = CKM_CAST128_CBC;
pub const CKM_CAST128_CBC: CK_MECHANISM_TYPE = 0x00000322;
pub const CKM_CAST5_MAC: CK_MECHANISM_TYPE = CKM_CAST128_MAC;
pub const CKM_CAST128_MAC: CK_MECHANISM_TYPE = 0x00000323;
pub const CKM_CAST5_MAC_GENERAL: CK_MECHANISM_TYPE = CKM_CAST128_MAC_GENERAL;
pub const CKM_CAST128_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000324;
pub const CKM_CAST5_CBC_PAD: CK_MECHANISM_TYPE = CKM_CAST128_CBC_PAD;
pub const CKM_CAST128_CBC_PAD: CK_MECHANISM_TYPE = 0x00000325;
pub const CKM_RC5_KEY_GEN: CK_MECHANISM_TYPE = 0x00000330;
pub const CKM_RC5_ECB: CK_MECHANISM_TYPE = 0x00000331;
pub const CKM_RC5_CBC: CK_MECHANISM_TYPE = 0x00000332;
pub const CKM_RC5_MAC: CK_MECHANISM_TYPE = 0x00000333;
pub const CKM_RC5_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000334;
pub const CKM_RC5_CBC_PAD: CK_MECHANISM_TYPE = 0x00000335;
pub const CKM_IDEA_KEY_GEN: CK_MECHANISM_TYPE = 0x00000340;
pub const CKM_IDEA_ECB: CK_MECHANISM_TYPE = 0x00000341;
pub const CKM_IDEA_CBC: CK_MECHANISM_TYPE = 0x00000342;
pub const CKM_IDEA_MAC: CK_MECHANISM_TYPE = 0x00000343;
pub const CKM_IDEA_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000344;
pub const CKM_IDEA_CBC_PAD: CK_MECHANISM_TYPE = 0x00000345;
pub const CKM_GENERIC_SECRET_KEY_GEN: CK_MECHANISM_TYPE = 0x00000350;
pub const CKM_CONCATENATE_BASE_AND_KEY: CK_MECHANISM_TYPE = 0x00000360;
pub const CKM_CONCATENATE_BASE_AND_DATA: CK_MECHANISM_TYPE = 0x00000362;
pub const CKM_CONCATENATE_DATA_AND_BASE: CK_MECHANISM_TYPE = 0x00000363;
pub const CKM_XOR_BASE_AND_DATA: CK_MECHANISM_TYPE = 0x00000364;
pub const CKM_EXTRACT_KEY_FROM_KEY: CK_MECHANISM_TYPE = 0x00000365;
pub const CKM_SSL3_PRE_MASTER_KEY_GEN: CK_MECHANISM_TYPE = 0x00000370;
pub const CKM_SSL3_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x00000371;
pub const CKM_SSL3_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x00000372;
pub const CKM_SSL3_MASTER_KEY_DERIVE_DH: CK_MECHANISM_TYPE = 0x00000373;
pub const CKM_TLS_PRE_MASTER_KEY_GEN: CK_MECHANISM_TYPE = 0x00000374;
pub const CKM_TLS_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x00000375;
pub const CKM_TLS_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x00000376;
pub const CKM_TLS_MASTER_KEY_DERIVE_DH: CK_MECHANISM_TYPE = 0x00000377;
pub const CKM_TLS_PRF: CK_MECHANISM_TYPE = 0x00000378;
pub const CKM_SSL3_MD5_MAC: CK_MECHANISM_TYPE = 0x00000380;
pub const CKM_SSL3_SHA1_MAC: CK_MECHANISM_TYPE = 0x00000381;
pub const CKM_MD5_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000390;
pub const CKM_MD2_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000391;
pub const CKM_SHA1_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000392;
pub const CKM_SHA256_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000393;
pub const CKM_SHA384_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000394;
pub const CKM_SHA512_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000395;
pub const CKM_PBE_MD2_DES_CBC: CK_MECHANISM_TYPE = 0x000003A0;
pub const CKM_PBE_MD5_DES_CBC: CK_MECHANISM_TYPE = 0x000003A1;
pub const CKM_PBE_MD5_CAST_CBC: CK_MECHANISM_TYPE = 0x000003A2;
pub const CKM_PBE_MD5_CAST3_CBC: CK_MECHANISM_TYPE = 0x000003A3;
pub const CKM_PBE_MD5_CAST5_CBC: CK_MECHANISM_TYPE = CKM_PBE_MD5_CAST128_CBC;
pub const CKM_PBE_MD5_CAST128_CBC: CK_MECHANISM_TYPE = 0x000003A4;
pub const CKM_PBE_SHA1_CAST5_CBC: CK_MECHANISM_TYPE = CKM_PBE_SHA1_CAST128_CBC;
pub const CKM_PBE_SHA1_CAST128_CBC: CK_MECHANISM_TYPE = 0x000003A5;
pub const CKM_PBE_SHA1_RC4_128: CK_MECHANISM_TYPE = 0x000003A6;
pub const CKM_PBE_SHA1_RC4_40: CK_MECHANISM_TYPE = 0x000003A7;
pub const CKM_PBE_SHA1_DES3_EDE_CBC: CK_MECHANISM_TYPE = 0x000003A8;
pub const CKM_PBE_SHA1_DES2_EDE_CBC: CK_MECHANISM_TYPE = 0x000003A9;
pub const CKM_PBE_SHA1_RC2_128_CBC: CK_MECHANISM_TYPE = 0x000003AA;
pub const CKM_PBE_SHA1_RC2_40_CBC: CK_MECHANISM_TYPE = 0x000003AB;
pub const CKM_PKCS5_PBKD2: CK_MECHANISM_TYPE = 0x000003B0;
pub const CKM_PBA_SHA1_WITH_SHA1_HMAC: CK_MECHANISM_TYPE = 0x000003C0;
pub const CKM_WTLS_PRE_MASTER_KEY_GEN: CK_MECHANISM_TYPE = 0x000003D0;
pub const CKM_WTLS_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x000003D1;
pub const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC: CK_MECHANISM_TYPE = 0x000003D2;
pub const CKM_WTLS_PRF: CK_MECHANISM_TYPE = 0x000003D3;
pub const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x000003D4;
pub const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x000003D5;
pub const CKM_TLS10_MAC_SERVER: CK_MECHANISM_TYPE = 0x000003D6;
pub const CKM_TLS10_MAC_CLIENT: CK_MECHANISM_TYPE = 0x000003D7;
pub const CKM_TLS12_MAC: CK_MECHANISM_TYPE = 0x000003D8;
pub const CKM_TLS12_KDF: CK_MECHANISM_TYPE = 0x000003D9;
pub const CKM_TLS12_MASTER_KEY_DERIVE: CK_MECHANISM_TYPE = 0x000003E0;
pub const CKM_TLS12_KEY_AND_MAC_DERIVE: CK_MECHANISM_TYPE = 0x000003E1;
pub const CKM_TLS12_MASTER_KEY_DERIVE_DH: CK_MECHANISM_TYPE = 0x000003E2;
pub const CKM_TLS12_KEY_SAFE_DERIVE: CK_MECHANISM_TYPE = 0x000003E3;
pub const CKM_TLS_MAC: CK_MECHANISM_TYPE = 0x000003E4;
pub const CKM_TLS_KDF: CK_MECHANISM_TYPE = 0x000003E5;
pub const CKM_KEY_WRAP_LYNKS: CK_MECHANISM_TYPE = 0x00000400;
pub const CKM_KEY_WRAP_SET_OAEP: CK_MECHANISM_TYPE = 0x00000401;
pub const CKM_CMS_SIG: CK_MECHANISM_TYPE = 0x00000500;
pub const CKM_KIP_DERIVE: CK_MECHANISM_TYPE = 0x00000510;
pub const CKM_KIP_WRAP: CK_MECHANISM_TYPE = 0x00000511;
pub const CKM_KIP_MAC: CK_MECHANISM_TYPE = 0x00000512;
pub const CKM_CAMELLIA_KEY_GEN: CK_MECHANISM_TYPE = 0x00000550;
pub const CKM_CAMELLIA_CTR: CK_MECHANISM_TYPE = 0x00000558;
pub const CKM_ARIA_KEY_GEN: CK_MECHANISM_TYPE = 0x00000560;
pub const CKM_ARIA_ECB: CK_MECHANISM_TYPE = 0x00000561;
pub const CKM_ARIA_CBC: CK_MECHANISM_TYPE = 0x00000562;
pub const CKM_ARIA_MAC: CK_MECHANISM_TYPE = 0x00000563;
pub const CKM_ARIA_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000564;
pub const CKM_ARIA_CBC_PAD: CK_MECHANISM_TYPE = 0x00000565;
pub const CKM_ARIA_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000566;
pub const CKM_ARIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000567;
pub const CKM_SEED_KEY_GEN: CK_MECHANISM_TYPE = 0x00000650;
pub const CKM_SEED_ECB: CK_MECHANISM_TYPE = 0x00000651;
pub const CKM_SEED_CBC: CK_MECHANISM_TYPE = 0x00000652;
pub const CKM_SEED_MAC: CK_MECHANISM_TYPE = 0x00000653;
pub const CKM_SEED_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000654;
pub const CKM_SEED_CBC_PAD: CK_MECHANISM_TYPE = 0x00000655;
pub const CKM_SEED_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000656;
pub const CKM_SEED_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000657;
pub const CKM_SKIPJACK_KEY_GEN: CK_MECHANISM_TYPE = 0x00001000;
pub const CKM_SKIPJACK_ECB64: CK_MECHANISM_TYPE = 0x00001001;
pub const CKM_SKIPJACK_CBC64: CK_MECHANISM_TYPE = 0x00001002;
pub const CKM_SKIPJACK_OFB64: CK_MECHANISM_TYPE = 0x00001003;
pub const CKM_SKIPJACK_CFB64: CK_MECHANISM_TYPE = 0x00001004;
pub const CKM_SKIPJACK_CFB32: CK_MECHANISM_TYPE = 0x00001005;
pub const CKM_SKIPJACK_CFB16: CK_MECHANISM_TYPE = 0x00001006;
pub const CKM_SKIPJACK_CFB8: CK_MECHANISM_TYPE = 0x00001007;
pub const CKM_SKIPJACK_WRAP: CK_MECHANISM_TYPE = 0x00001008;
pub const CKM_SKIPJACK_PRIVATE_WRAP: CK_MECHANISM_TYPE = 0x00001009;
pub const CKM_SKIPJACK_RELAYX: CK_MECHANISM_TYPE = 0x0000100a;
pub const CKM_KEA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001010;
pub const CKM_KEA_KEY_DERIVE: CK_MECHANISM_TYPE = 0x00001011;
pub const CKM_FORTEZZA_TIMESTAMP: CK_MECHANISM_TYPE = 0x00001020;
pub const CKM_BATON_KEY_GEN: CK_MECHANISM_TYPE = 0x00001030;
pub const CKM_BATON_ECB128: CK_MECHANISM_TYPE = 0x00001031;
pub const CKM_BATON_ECB96: CK_MECHANISM_TYPE = 0x00001032;
pub const CKM_BATON_CBC128: CK_MECHANISM_TYPE = 0x00001033;
pub const CKM_BATON_COUNTER: CK_MECHANISM_TYPE = 0x00001034;
pub const CKM_BATON_SHUFFLE: CK_MECHANISM_TYPE = 0x00001035;
pub const CKM_BATON_WRAP: CK_MECHANISM_TYPE = 0x00001036;
pub const CKM_ECDSA_KEY_PAIR_GEN: CK_MECHANISM_TYPE = CKM_EC_KEY_PAIR_GEN;
pub const CKM_EC_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001040;
pub const CKM_ECDSA: CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA1: CK_MECHANISM_TYPE = 0x00001042;
pub const CKM_ECDSA_SHA224: CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_ECDSA_SHA256: CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_ECDSA_SHA384: CK_MECHANISM_TYPE = 0x00001045;
pub const CKM_ECDSA_SHA512: CK_MECHANISM_TYPE = 0x00001046;
pub const CKM_ECDH1_DERIVE: CK_MECHANISM_TYPE = 0x00001050;
pub const CKM_ECDH1_COFACTOR_DERIVE: CK_MECHANISM_TYPE = 0x00001051;
pub const CKM_ECMQV_DERIVE: CK_MECHANISM_TYPE = 0x00001052;
pub const CKM_ECDH_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x00001053;
pub const CKM_RSA_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x00001054;
pub const CKM_JUNIPER_KEY_GEN: CK_MECHANISM_TYPE = 0x00001060;
pub const CKM_JUNIPER_ECB128: CK_MECHANISM_TYPE = 0x00001061;
pub const CKM_JUNIPER_CBC128: CK_MECHANISM_TYPE = 0x00001062;
pub const CKM_JUNIPER_COUNTER: CK_MECHANISM_TYPE = 0x00001063;
pub const CKM_JUNIPER_SHUFFLE: CK_MECHANISM_TYPE = 0x00001064;
pub const CKM_JUNIPER_WRAP: CK_MECHANISM_TYPE = 0x00001065;
pub const CKM_FASTHASH: CK_MECHANISM_TYPE = 0x00001070;
pub const CKM_AES_KEY_GEN: CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_ECB: CK_MECHANISM_TYPE = 0x00001081;
pub const CKM_AES_CBC: CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_MAC: CK_MECHANISM_TYPE = 0x00001083;
pub const CKM_AES_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00001084;
pub const CKM_AES_CBC_PAD: CK_MECHANISM_TYPE = 0x00001085;
pub const CKM_AES_CTR: CK_MECHANISM_TYPE = 0x00001086;
pub const CKM_AES_GCM: CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_AES_CCM: CK_MECHANISM_TYPE = 0x00001088;
pub const CKM_AES_CTS: CK_MECHANISM_TYPE = 0x00001089;
pub const CKM_AES_CMAC: CK_MECHANISM_TYPE = 0x0000108A;
pub const CKM_AES_CMAC_GENERAL: CK_MECHANISM_TYPE = 0x0000108B;
pub const CKM_AES_XCBC_MAC: CK_MECHANISM_TYPE = 0x0000108C;
pub const CKM_AES_XCBC_MAC_96: CK_MECHANISM_TYPE = 0x0000108D;
pub const CKM_AES_GMAC: CK_MECHANISM_TYPE = 0x0000108E;
pub const CKM_BLOWFISH_KEY_GEN: CK_MECHANISM_TYPE = 0x00001090;
pub const CKM_BLOWFISH_CBC: CK_MECHANISM_TYPE = 0x00001091;
pub const CKM_TWOFISH_KEY_GEN: CK_MECHANISM_TYPE = 0x00001092;
pub const CKM_TWOFISH_CBC: CK_MECHANISM_TYPE = 0x00001093;
pub const CKM_BLOWFISH_CBC_PAD: CK_MECHANISM_TYPE = 0x00001094;
pub const CKM_TWOFISH_CBC_PAD: CK_MECHANISM_TYPE = 0x00001095;
pub const CKM_DES_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001100;
pub const CKM_DES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001101;
pub const CKM_DES3_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001102;
pub const CKM_DES3_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001103;
pub const CKM_AES_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001104;
pub const CKM_AES_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00001105;
pub const CKM_GOSTR3410_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001200;
pub const CKM_GOSTR3410: CK_MECHANISM_TYPE = 0x00001201;
pub const CKM_GOSTR3410_WITH_GOSTR3411: CK_MECHANISM_TYPE = 0x00001202;
pub const CKM_GOSTR3410_KEY_WRAP: CK_MECHANISM_TYPE = 0x00001203;
pub const CKM_GOSTR3410_DERIVE: CK_MECHANISM_TYPE = 0x00001204;
pub const CKM_GOSTR3411: CK_MECHANISM_TYPE = 0x00001210;
pub const CKM_GOSTR3411_HMAC: CK_MECHANISM_TYPE = 0x00001211;
pub const CKM_GOST28147_KEY_GEN: CK_MECHANISM_TYPE = 0x00001220;
pub const CKM_GOST28147_ECB: CK_MECHANISM_TYPE = 0x00001221;
pub const CKM_GOST28147: CK_MECHANISM_TYPE = 0x00001222;
pub const CKM_GOST28147_MAC: CK_MECHANISM_TYPE = 0x00001223;
pub const CKM_GOST28147_KEY_WRAP: CK_MECHANISM_TYPE = 0x00001224;
pub const CKM_DSA_PARAMETER_GEN: CK_MECHANISM_TYPE = 0x00002000;
pub const CKM_DH_PKCS_PARAMETER_GEN: CK_MECHANISM_TYPE = 0x00002001;
pub const CKM_X9_42_DH_PARAMETER_GEN: CK_MECHANISM_TYPE = 0x00002002;
pub const CKM_DSA_PROBABLISTIC_PARAMETER_GEN: CK_MECHANISM_TYPE = 0x00002003;
pub const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN: CK_MECHANISM_TYPE = 0x00002004;
pub const CKM_AES_OFB: CK_MECHANISM_TYPE = 0x00002104;
pub const CKM_AES_CFB64: CK_MECHANISM_TYPE = 0x00002105;
pub const CKM_AES_CFB8: CK_MECHANISM_TYPE = 0x00002106;
pub const CKM_AES_CFB128: CK_MECHANISM_TYPE = 0x00002107;
pub const CKM_AES_CFB1: CK_MECHANISM_TYPE = 0x00002108;
pub const CKM_VENDOR_DEFINED: CK_MECHANISM_TYPE = 0x80000000;
pub const CKM_SHA224: CK_MECHANISM_TYPE = 0x00000255;
pub const CKM_SHA224_HMAC: CK_MECHANISM_TYPE = 0x00000256;
pub const CKM_SHA224_HMAC_GENERAL: CK_MECHANISM_TYPE = 0x00000257;
pub const CKM_SHA224_RSA_PKCS: CK_MECHANISM_TYPE = 0x00000046;
pub const CKM_SHA224_RSA_PKCS_PSS: CK_MECHANISM_TYPE = 0x00000047;
pub const CKM_SHA224_KEY_DERIVATION: CK_MECHANISM_TYPE = 0x00000396;
pub const CKM_CAMELLIA_ECB: CK_MECHANISM_TYPE = 0x00000551;
pub const CKM_CAMELLIA_CBC: CK_MECHANISM_TYPE = 0x00000552;
pub const CKM_CAMELLIA_MAC: CK_MECHANISM_TYPE = 0x00000553;
pub const CKM_CAMELLIA_MAC_GENERAL: CK_MECHANISM_TYPE = 0x00000554;
pub const CKM_CAMELLIA_CBC_PAD: CK_MECHANISM_TYPE = 0x00000555;
pub const CKM_CAMELLIA_ECB_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000556;
pub const CKM_CAMELLIA_CBC_ENCRYPT_DATA: CK_MECHANISM_TYPE = 0x00000557;
pub const CKM_AES_KEY_WRAP: CK_MECHANISM_TYPE = 0x00002109;
pub const CKM_AES_KEY_WRAP_PAD: CK_MECHANISM_TYPE = 0x0000210A;
pub const CKM_RSA_PKCS_TPM_1_1: CK_MECHANISM_TYPE = 0x00004001;
pub const CKM_RSA_PKCS_OAEP_TPM_1_1: CK_MECHANISM_TYPE = 0x00004002;
pub const CKM_EC_EDWARDS_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001055;
pub const CKM_EC_MONTGOMERY_KEY_PAIR_GEN: CK_MECHANISM_TYPE = 0x00001056;
pub const CKM_EDDSA: CK_MECHANISM_TYPE = 0x00001057; // Backport from PKCS#11 v3
pub const CKM_BIP32_CHILD_DERIVE: CK_MECHANISM_TYPE = CKM_VENDOR_DEFINED + 0xE01;
pub const CKM_BIP32_MASTER_DERIVE: CK_MECHANISM_TYPE = CKM_VENDOR_DEFINED + 0xE00;
pub const CKM_AES_KWP: CK_MECHANISM_TYPE = CKM_VENDOR_DEFINED + 0x171;
pub const CK_OTP_FORMAT_DECIMAL: CK_ULONG = 0;
pub const CK_OTP_FORMAT_HEXADECIMAL: CK_ULONG = 1;
pub const CK_OTP_FORMAT_ALPHANUMERIC: CK_ULONG = 2;
pub const CK_OTP_FORMAT_BINARY: CK_ULONG = 3;
pub const CK_OTP_PARAM_IGNORED: CK_ULONG = 0;
pub const CK_OTP_PARAM_OPTIONAL: CK_ULONG = 1;
pub const CK_OTP_PARAM_MANDATORY: CK_ULONG = 2;
pub const CK_OTP_VALUE: CK_ULONG = 0;
pub const CK_OTP_PIN: CK_ULONG = 1;
pub const CK_OTP_CHALLENGE: CK_ULONG = 2;
pub const CK_OTP_TIME: CK_ULONG = 3;
pub const CK_OTP_COUNTER: CK_ULONG = 4;
pub const CK_OTP_FLAGS: CK_ULONG = 5;
pub const CK_OTP_OUTPUT_LENGTH: CK_ULONG = 6;
pub const CKF_NEXT_OTP: CK_FLAGS = 0x00000001;
pub const CKF_EXCLUDE_TIME: CK_FLAGS = 0x00000002;
pub const CKF_EXCLUDE_COUNTER: CK_FLAGS = 0x00000004;
pub const CKF_EXCLUDE_CHALLENGE: CK_FLAGS = 0x00000008;
pub const CKF_EXCLUDE_PIN: CK_FLAGS = 0x00000010;
pub const CKF_USER_FRIENDLY_OTP: CK_FLAGS = 0x00000020;
pub const CKN_OTP_CHANGED: CK_NOTIFICATION = 1;
pub const CKG_MGF1_SHA1: CK_RSA_PKCS_MGF_TYPE = 0x00000001;
pub const CKG_MGF1_SHA224: CK_RSA_PKCS_MGF_TYPE = 0x00000005;
pub const CKG_MGF1_SHA256: CK_RSA_PKCS_MGF_TYPE = 0x00000002;
pub const CKG_MGF1_SHA384: CK_RSA_PKCS_MGF_TYPE = 0x00000003;
pub const CKG_MGF1_SHA512: CK_RSA_PKCS_MGF_TYPE = 0x00000004;
pub const CKG_BIP32_MAX_SERIALIZED_LEN: CK_BIP32_GENERATION_TYPE = 0x00000070;
pub const CKG_BIP32_VERSION_MAINNET_PUB: CK_BIP32_GENERATION_TYPE = 0x0488B21E;
pub const CKG_BIP32_VERSION_MAINNET_PRIV: CK_BIP32_GENERATION_TYPE = 0x0488ADE4;
pub const CKG_BIP32_VERSION_TESTNET_PUB: CK_BIP32_GENERATION_TYPE = 0x043587CF;
pub const CKG_BIP32_VERSION_TESTNET_PRIV: CK_BIP32_GENERATION_TYPE = 0x04358394;
pub const CKG_BIP44_PURPOSE: CK_BIP44_GENERATION_TYPE = 0x0000002C;
pub const CKG_BIP44_COIN_TYPE_BTC: CK_BIP44_GENERATION_TYPE = 0x00000000;
pub const CKG_BIP44_COIN_TYPE_BTC_TESTNET: CK_BIP44_GENERATION_TYPE = 0x00000001;
pub const CKG_BIP32_EXTERNAL_CHAIN: CK_BIP32_GENERATION_TYPE = 0x00000000;
pub const CKG_BIP32_INTERNAL_CHAIN: CK_BIP32_GENERATION_TYPE = 0x00000001;
pub const CKD_NULL: CK_EC_KDF_TYPE = 0x00000001;
pub const CKD_SHA1_KDF: CK_EC_KDF_TYPE = 0x00000002;
pub const CKD_SHA1_KDF_ASN1: CK_X9_42_DH_KDF_TYPE = 0x00000003;
pub const CKD_SHA1_KDF_CONCATENATE: CK_X9_42_DH_KDF_TYPE = 0x00000004;
pub const CKD_SHA224_KDF: CK_X9_42_DH_KDF_TYPE = 0x00000005;
pub const CKD_SHA256_KDF: CK_X9_42_DH_KDF_TYPE = 0x00000006;
pub const CKD_SHA384_KDF: CK_X9_42_DH_KDF_TYPE = 0x00000007;
pub const CKD_SHA512_KDF: CK_X9_42_DH_KDF_TYPE = 0x00000008;
pub const CKD_CPDIVERSIFY_KDF: CK_X9_42_DH_KDF_TYPE = 0x00000009;
pub const CKF_HW: CK_FLAGS = 0x00000001; /* performed by HW */
pub const CKF_ENCRYPT: CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT: CK_FLAGS = 0x00000200;
pub const CKF_DIGEST: CK_FLAGS = 0x00000400;
pub const CKF_SIGN: CK_FLAGS = 0x00000800;
pub const CKF_SIGN_RECOVER: CK_FLAGS = 0x00001000;
pub const CKF_VERIFY: CK_FLAGS = 0x00002000;
pub const CKF_VERIFY_RECOVER: CK_FLAGS = 0x00004000;
pub const CKF_GENERATE: CK_FLAGS = 0x00008000;
pub const CKF_GENERATE_KEY_PAIR: CK_FLAGS = 0x00010000;
pub const CKF_WRAP: CK_FLAGS = 0x00020000;
pub const CKF_UNWRAP: CK_FLAGS = 0x00040000;
pub const CKF_DERIVE: CK_FLAGS = 0x00080000;
pub const CKF_EXTENSION: CK_FLAGS = 0x80000000;
pub const CKF_EC_F_P: CK_FLAGS = 0x00100000;
pub const CKF_EC_F_2M: CK_FLAGS = 0x00200000;
pub const CKF_EC_ECPARAMETERS: CK_FLAGS = 0x00400000;
pub const CKF_EC_NAMEDCURVE: CK_FLAGS = 0x00800000;
pub const CKF_EC_UNCOMPRESS: CK_FLAGS = 0x01000000;
pub const CKF_EC_COMPRESS: CK_FLAGS = 0x02000000;
pub const CKF_DONT_BLOCK: CK_FLAGS = 1;
pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = 0x00000001;
pub const CKF_OS_LOCKING_OK: CK_FLAGS = 0x00000002;
pub const CKF_BIP32_MAX_PATH_LEN: CK_FLAGS = 0x000000FF;
pub const CKF_BIP32_HARDENED: CK_FLAGS = 0x80000000;
pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_CANCEL: CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY: CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED: CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_NO_EVENT: CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS: CK_RV = 0x00000009;
pub const CKR_CANT_LOCK: CK_RV = 0x0000000A;
pub const CKR_ATTRIBUTE_READ_ONLY: CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE: CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID: CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID: CK_RV = 0x00000013;
pub const CKR_ACTION_PROHIBITED: CK_RV = 0x0000001B;
pub const CKR_DATA_INVALID: CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE: CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR: CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY: CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED: CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID: CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE: CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED: CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL: CK_RV = 0x00000051;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_CURVE_NOT_SUPPORTED: CK_RV = 0x00000140;
pub const CKR_KEY_HANDLE_INVALID: CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE: CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000063;
pub const CKR_KEY_NOT_NEEDED: CK_RV = 0x00000064;
pub const CKR_KEY_CHANGED: CK_RV = 0x00000065;
pub const CKR_KEY_NEEDED: CK_RV = 0x00000066;
pub const CKR_KEY_INDIGESTIBLE: CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED: CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE: CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE: CK_RV = 0x0000006A;
pub const CKR_MECHANISM_INVALID: CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID: CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE: CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT: CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID: CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE: CK_RV = 0x000000A2;
pub const CKR_PIN_EXPIRED: CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED: CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED: CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT: CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED: CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY: CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS: CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS: CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS: CK_RV = 0x000000B8;
pub const CKR_SIGNATURE_INVALID: CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE: CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE: CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT: CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT: CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED: CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED: CK_RV = 0x000000E2;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x000000F0;
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE: CK_RV = 0x000000F1;
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x000000F2;
pub const CKR_USER_ALREADY_LOGGED_IN: CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN: CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED: CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID: CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN: CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES: CK_RV = 0x00000105;
pub const CKR_WRAPPED_KEY_INVALID: CK_RV = 0x00000110;
pub const CKR_WRAPPED_KEY_LEN_RANGE: CK_RV = 0x00000112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID: CK_RV = 0x00000113;
pub const CKR_WRAPPING_KEY_SIZE_RANGE: CK_RV = 0x00000114;
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT: CK_RV = 0x00000115;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED: CK_RV = 0x00000120;
pub const CKR_RANDOM_NO_RNG: CK_RV = 0x00000121;
pub const CKR_DOMAIN_PARAMS_INVALID: CK_RV = 0x00000130;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_SAVED_STATE_INVALID: CK_RV = 0x00000160;
pub const CKR_INFORMATION_SENSITIVE: CK_RV = 0x00000170;
pub const CKR_STATE_UNSAVEABLE: CK_RV = 0x00000180;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD: CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED: CK_RV = 0x000001A1;
pub const CKR_NEW_PIN_MODE: CK_RV = 0x000001B0;
pub const CKR_NEXT_OTP: CK_RV = 0x000001B1;
pub const CKR_EXCEEDED_MAX_ITERATIONS: CK_RV = 0x000001B5;
pub const CKR_FIPS_SELF_TEST_FAILED: CK_RV = 0x000001B6;
pub const CKR_LIBRARY_LOAD_FAILED: CK_RV = 0x000001B7;
pub const CKR_PIN_TOO_WEAK: CK_RV = 0x000001B8;
pub const CKR_PUBLIC_KEY_INVALID: CK_RV = 0x000001B9;
pub const CKR_FUNCTION_REJECTED: CK_RV = 0x00000200;
pub const CKR_VENDOR_DEFINED: CK_RV = 0x80000000;
pub const CKZ_DATA_SPECIFIED: CK_RSA_PKCS_OAEP_SOURCE_TYPE = 0x00000001;
pub const CK_FALSE: CK_BBOOL = 0;
pub const CK_TRUE: CK_BBOOL = 1;
//CKR_VENDOR_DEFINED for Luna HSM
pub const CKR_RC_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x04;
pub const CKR_CONTAINER_HANDLE_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x05;
pub const CKR_TOO_MANY_CONTAINERS: CK_RV = CKR_VENDOR_DEFINED + 0x06;
pub const CKR_USER_LOCKED_OUT: CK_RV = CKR_VENDOR_DEFINED + 0x07;
pub const CKR_CLONING_PARAMETER_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x08;
pub const CKR_CLONING_PARAMETER_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x09;
pub const CKR_CERTIFICATE_DATA_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x0a;
pub const CKR_CERTIFICATE_DATA_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x0b;
pub const CKR_ACCEL_DEVICE_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x0c;
pub const CKR_WRAPPING_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x0d;
pub const CKR_UNWRAPPING_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x0e;
pub const CKR_MAC_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x0f;
pub const CKR_DAC_POLICY_PID_MISMATCH: CK_RV = CKR_VENDOR_DEFINED + 0x10;
pub const CKR_DAC_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x11;
pub const CKR_BAD_DAC: CK_RV = CKR_VENDOR_DEFINED + 0x12;
pub const CKR_SSK_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x13;
pub const CKR_BAD_MAC: CK_RV = CKR_VENDOR_DEFINED + 0x14;
pub const CKK_BIP32: CK_KEY_TYPE = CKK_VENDOR_DEFINED + 0x14;
pub const CKR_DAK_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x15;
pub const CKR_BAD_DAK: CK_RV = CKR_VENDOR_DEFINED + 0x16;
pub const CKR_SIM_AUTHORIZATION_FAILED: CK_RV = CKR_VENDOR_DEFINED + 0x17;
pub const CKR_SIM_VERSION_UNSUPPORTED: CK_RV = CKR_VENDOR_DEFINED + 0x18;
pub const CKR_SIM_CORRUPT_DATA: CK_RV = CKR_VENDOR_DEFINED + 0x19;
pub const CKR_USER_NOT_AUTHORIZED: CK_RV = CKR_VENDOR_DEFINED + 0x1a;
pub const CKR_MAX_OBJECT_COUNT_EXCEEDED: CK_RV = CKR_VENDOR_DEFINED + 0x1b;
pub const CKR_SO_LOGIN_FAILURE_THRESHOLD: CK_RV = CKR_VENDOR_DEFINED + 0x1c;
pub const CKR_SIM_AUTHFORM_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x1d;
pub const CKR_CITS_DAK_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x1e;
pub const CKR_UNABLE_TO_CONNECT: CK_RV = CKR_VENDOR_DEFINED + 0x1f;
pub const CKR_PARTITION_DISABLED: CK_RV = CKR_VENDOR_DEFINED + 0x20;
pub const CKR_CALLBACK_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x21;
pub const CKR_SECURITY_PARAMETER_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x22;
pub const CKR_SP_TIMEOUT: CK_RV = CKR_VENDOR_DEFINED + 0x23;
pub const CKR_TIMEOUT: CK_RV = CKR_VENDOR_DEFINED + 0x24;
pub const CKR_ECC_UNKNOWN_CURVE: CK_RV = CKR_VENDOR_DEFINED + 0x25;
pub const CKR_MTK_ZEROIZED: CK_RV = CKR_VENDOR_DEFINED + 0x26;
pub const CKR_MTK_STATE_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x27;
pub const CKR_INVALID_ENTRY_TYPE: CK_RV = CKR_VENDOR_DEFINED + 0x28;
pub const CKR_MTK_SPLIT_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x29;
pub const CKR_HSM_STORAGE_FULL: CK_RV = CKR_VENDOR_DEFINED + 0x2a;
pub const CKR_DEVICE_TIMEOUT: CK_RV = CKR_VENDOR_DEFINED + 0x2b;
pub const CKR_CONTAINER_OBJECT_STORAGE_FULL: CK_RV = CKR_VENDOR_DEFINED + 0x2C;
pub const CKR_PED_CLIENT_NOT_RUNNING: CK_RV = CKR_VENDOR_DEFINED + 0x2D;
pub const CKR_PED_UNPLUGGED: CK_RV = CKR_VENDOR_DEFINED + 0x2E;
pub const CKR_ECC_POINT_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x2F;
pub const CKR_OPERATION_NOT_ALLOWED: CK_RV = CKR_VENDOR_DEFINED + 0x30;
pub const CKR_LICENSE_CAPACITY_EXCEEDED: CK_RV = CKR_VENDOR_DEFINED + 0x31;
pub const CKR_LOG_FILE_NOT_OPEN: CK_RV = CKR_VENDOR_DEFINED + 0x32;
pub const CKR_LOG_FILE_WRITE_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x33;
pub const CKR_LOG_BAD_FILE_NAME: CK_RV = CKR_VENDOR_DEFINED + 0x34;
pub const CKR_LOG_FULL: CK_RV = CKR_VENDOR_DEFINED + 0x35;
pub const CKR_LOG_NO_KCV: CK_RV = CKR_VENDOR_DEFINED + 0x36;
pub const CKR_LOG_BAD_RECORD_HMAC: CK_RV = CKR_VENDOR_DEFINED + 0x37;
pub const CKR_LOG_BAD_TIME: CK_RV = CKR_VENDOR_DEFINED + 0x38;
pub const CKR_LOG_AUDIT_NOT_INITIALIZED: CK_RV = CKR_VENDOR_DEFINED + 0x39;
pub const CKR_LOG_RESYNC_NEEDED: CK_RV = CKR_VENDOR_DEFINED + 0x3A;
pub const CKR_AUDIT_LOGIN_TIMEOUT_IN_PROGRESS: CK_RV = CKR_VENDOR_DEFINED + 0x3B;
pub const CKR_AUDIT_LOGIN_FAILURE_THRESHOLD: CK_RV = CKR_VENDOR_DEFINED + 0x3C;
pub const CKR_INVALID_FUF_TARGET: CK_RV = CKR_VENDOR_DEFINED + 0x3D;
pub const CKR_INVALID_FUF_HEADER: CK_RV = CKR_VENDOR_DEFINED + 0x3E;
pub const CKR_INVALID_FUF_VERSION: CK_RV = CKR_VENDOR_DEFINED + 0x3F;
pub const CKR_ECC_ECC_RESULT_AT_INF: CK_RV = CKR_VENDOR_DEFINED + 0x40;
pub const CKR_AGAIN: CK_RV = CKR_VENDOR_DEFINED + 0x41;
pub const CKR_TOKEN_COPIED: CK_RV = CKR_VENDOR_DEFINED + 0x42;
pub const CKR_SLOT_NOT_EMPTY: CK_RV = CKR_VENDOR_DEFINED + 0x43;
pub const CKR_USER_ALREADY_ACTIVATED: CK_RV = CKR_VENDOR_DEFINED + 0x44;
pub const CKR_STC_NO_CONTEXT: CK_RV = CKR_VENDOR_DEFINED + 0x45;
pub const CKR_STC_CLIENT_IDENTITY_NOT_CONFIGURED: CK_RV = CKR_VENDOR_DEFINED + 0x46;
pub const CKR_STC_PARTITION_IDENTITY_NOT_CONFIGURED: CK_RV = CKR_VENDOR_DEFINED + 0x47;
pub const CKR_STC_DH_KEYGEN_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x48;
pub const CKR_STC_CIPHER_SUITE_REJECTED: CK_RV = CKR_VENDOR_DEFINED + 0x49;
pub const CKR_STC_DH_KEY_NOT_FROM_SAME_GROUP: CK_RV = CKR_VENDOR_DEFINED + 0x4a;
pub const CKR_STC_COMPUTE_DH_KEY_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x4b;
pub const CKR_STC_FIRST_PHASE_KDF_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x4c;
pub const CKR_STC_SECOND_PHASE_KDF_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x4d;
pub const CKR_STC_KEY_CONFIRMATION_FAILED: CK_RV = CKR_VENDOR_DEFINED + 0x4e;
pub const CKR_STC_NO_SESSION_KEY: CK_RV = CKR_VENDOR_DEFINED + 0x4f;
pub const CKR_STC_RESPONSE_BAD_MAC: CK_RV = CKR_VENDOR_DEFINED + 0x50;
pub const CKR_STC_NOT_ENABLED: CK_RV = CKR_VENDOR_DEFINED + 0x51;
pub const CKR_STC_CLIENT_HANDLE_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x52;
pub const CKR_STC_SESSION_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x53;
pub const CKR_STC_CONTAINER_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x54;
pub const CKR_STC_SEQUENCE_NUM_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x55;
pub const CKR_STC_NO_CHANNEL: CK_RV = CKR_VENDOR_DEFINED + 0x56;
pub const CKR_STC_RESPONSE_DECRYPT_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x57;
pub const CKR_STC_RESPONSE_REPLAYED: CK_RV = CKR_VENDOR_DEFINED + 0x58;
pub const CKR_STC_REKEY_CHANNEL_MISMATCH: CK_RV = CKR_VENDOR_DEFINED + 0x59;
pub const CKR_STC_RSA_ENCRYPT_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x5a;
pub const CKR_STC_RSA_SIGN_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x5b;
pub const CKR_STC_RSA_DECRYPT_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x5c;
pub const CKR_STC_RESPONSE_UNEXPECTED_KEY: CK_RV = CKR_VENDOR_DEFINED + 0x5d;
pub const CKR_STC_UNEXPECTED_NONCE_PAYLOAD_SIZE: CK_RV = CKR_VENDOR_DEFINED + 0x5e;
pub const CKR_STC_UNEXPECTED_DH_DATA_SIZE: CK_RV = CKR_VENDOR_DEFINED + 0x5f;
pub const CKR_STC_OPEN_CIPHER_MISMATCH: CK_RV = CKR_VENDOR_DEFINED + 0x60;
pub const CKR_STC_OPEN_DHNIST_PUBKEY_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x61;
pub const CKR_STC_OPEN_KEY_MATERIAL_GEN_FAIL: CK_RV = CKR_VENDOR_DEFINED + 0x62;
pub const CKR_STC_OPEN_RESP_GEN_FAIL: CK_RV = CKR_VENDOR_DEFINED + 0x63;
pub const CKR_STC_ACTIVATE_MACTAG_U_VERIFY_FAIL: CK_RV = CKR_VENDOR_DEFINED + 0x64;
pub const CKR_STC_ACTIVATE_MACTAG_V_GEN_FAIL: CK_RV = CKR_VENDOR_DEFINED + 0x65;
pub const CKR_STC_ACTIVATE_RESP_GEN_FAIL: CK_RV = CKR_VENDOR_DEFINED + 0x66;
pub const CKR_CHALLENGE_INCORRECT: CK_RV = CKR_VENDOR_DEFINED + 0x67;
pub const CKR_ACCESS_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x68;
pub const CKR_ACCESS_ID_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x69;
pub const CKR_KEY_NOT_KEKABLE: CK_RV = CKR_VENDOR_DEFINED + 0x6a;
pub const CKR_MECHANISM_INVALID_FOR_FP: CK_RV = CKR_VENDOR_DEFINED + 0x6b;
pub const CKR_OPERATION_INVALID_FOR_FP: CK_RV = CKR_VENDOR_DEFINED + 0x6c;
pub const CKR_SESSION_HANDLE_INVALID_FOR_FP: CK_RV = CKR_VENDOR_DEFINED + 0x6d;
pub const CKR_CMD_NOT_ALLOWED_HSM_IN_TRANSPORT: CK_RV = CKR_VENDOR_DEFINED + 0x6e;
pub const CKR_OBJECT_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x6f;
pub const CKR_PARTITION_ROLE_DESC_VERSION_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x70;
pub const CKR_PARTITION_ROLE_POLICY_VERSION_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x71;
pub const CKR_PARTITION_ROLE_POLICY_SET_VERSION_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x72;
pub const CKR_REKEK_KEY: CK_RV = CKR_VENDOR_DEFINED + 0x73;
pub const CKR_KEK_RETRY_FAILURE: CK_RV = CKR_VENDOR_DEFINED + 0x74;
pub const CKR_RNG_RESEED_TOO_EARLY: CK_RV = CKR_VENDOR_DEFINED + 0x75;
pub const CKR_HSM_TAMPERED: CK_RV = CKR_VENDOR_DEFINED + 0x76;
pub const CKR_CONFIG_CHANGE_ILLEGAL: CK_RV = CKR_VENDOR_DEFINED + 0x77;
pub const CKR_SESSION_CONTEXT_NOT_ALLOCATED: CK_RV = CKR_VENDOR_DEFINED + 0x78;
pub const CKR_SESSION_CONTEXT_ALREADY_ALLOCATED: CK_RV = CKR_VENDOR_DEFINED + 0x79;
pub const CKR_INVALID_BL_ITB_AUTH_HEADER: CK_RV = CKR_VENDOR_DEFINED + 0x7A;
pub const CKR_POLICY_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x7B;
pub const CKR_CONFIG_ILLEGAL: CK_RV = CKR_VENDOR_DEFINED + 0x7C;
pub const CKR_CONFIG_FAILS_DEPENDENCIES: CK_RV = CKR_VENDOR_DEFINED + 0x7D;
pub const CKR_CERTIFICATE_TYPE_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x7E;
pub const CKR_INVALID_UTILIZATION_METRICS: CK_RV = CKR_VENDOR_DEFINED + 0x7F;
pub const CKR_UTILIZATION_BIN_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x80;
pub const CKR_UTILIZATION_COUNTER_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x81;
pub const CKR_INVALID_SERIAL_NUM: CK_RV = CKR_VENDOR_DEFINED + 0x82;
pub const CKR_BIP32_CHILD_INDEX_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x83;
pub const CKR_BIP32_INVALID_HARDENED_DERIVATION: CK_RV = CKR_VENDOR_DEFINED + 0x84;
pub const CKR_BIP32_MASTER_SEED_LEN_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x85;
pub const CKR_BIP32_MASTER_SEED_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x86;
pub const CKR_BIP32_INVALID_KEY_PATH_LEN: CK_RV = CKR_VENDOR_DEFINED + 0x87;
pub const CKR_FM_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x88;
pub const CKR_FM_NOT_SUPPORTED: CK_RV = CKR_VENDOR_DEFINED + 0x89;
pub const CKR_FM_NEVER_ENABLED: CK_RV = CKR_VENDOR_DEFINED + 0x8A;
pub const CKR_FM_DISABLED: CK_RV = CKR_VENDOR_DEFINED + 0x8B;
pub const CKR_FM_SMFS_INACTIVE: CK_RV = CKR_VENDOR_DEFINED + 0x8C;
pub const CKR_HSM_RESTART_REQUIRED: CK_RV = CKR_VENDOR_DEFINED + 0x8D;
pub const CKR_FM_CFG_ALLOWEDFLAG_DISABLED: CK_RV = CKR_VENDOR_DEFINED + 0x8E;
pub const CKR_ASSIGNED_KEY_REQUIRES_AUTH_DATA: CK_RV = CKR_VENDOR_DEFINED + 0x8F;
pub const CKR_ROLE_CANNOT_MAKE_KEYS_ASSIGNED: CK_RV = CKR_VENDOR_DEFINED + 0x90;
pub const CKR_ASSIGNED_KEY_CANNOT_BE_MODIFIED: CK_RV = CKR_VENDOR_DEFINED + 0x91;
pub const CKR_AUTH_DATA_TOO_LARGE: CK_RV = CKR_VENDOR_DEFINED + 0x92;
pub const CKR_AUTH_DATA_TOO_SMALL: CK_RV = CKR_VENDOR_DEFINED + 0x93;
pub const CKR_OH_AUTH_DATA_NOT_PROVIDED: CK_RV = CKR_VENDOR_DEFINED + 0x94;
pub const CKR_ASSIGNED_KEY_FAILED_ATTRIBUTE_DEPENDENCIES: CK_RV = CKR_VENDOR_DEFINED + 0x95;
pub const CKR_KEY_CANNOT_BE_AUTHORIZED: CK_RV = CKR_VENDOR_DEFINED + 0x96;
pub const CKR_KEY_NOT_AUTHORIZED: CK_RV = CKR_VENDOR_DEFINED + 0x97;
pub const CKR_AUTH_DATA_INCORRECT: CK_RV = CKR_VENDOR_DEFINED + 0x98;
pub const CKR_SMK_ID_NOT_FOUND: CK_RV = CKR_VENDOR_DEFINED + 0x99;
pub const CKR_INTERNAL_INTEGRITY_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x9A;
pub const CKR_ASSIGNED_KEY_CANNOT_BE_RESET: CK_RV = CKR_VENDOR_DEFINED + 0x9B;
pub const CKR_AUTH_DATA_INCORRECT_AND_LIMIT_REACHED: CK_RV = CKR_VENDOR_DEFINED + 0x9C;
pub const CKR_PED_UNSUPPORTED: CK_RV = CKR_VENDOR_DEFINED + 0x9D;
pub const CKR_PED_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x9E;
pub const CKR_ACCESS_ID_CONFLICT: CK_RV = CKR_VENDOR_DEFINED + 0x9F;
pub const CKR_STC_LOCKOUT: CK_RV = CKR_VENDOR_DEFINED + 0xA0;
pub const CKR_STC_ACTIVATION_TIMEOUT: CK_RV = CKR_VENDOR_DEFINED + 0xA1;
pub const CKR_STC_KEY_EXPIRED: CK_RV = CKR_VENDOR_DEFINED + 0xA2;
pub const CKR_KEY_INVALID_FOR_HA_LOGIN: CK_RV = CKR_VENDOR_DEFINED + 0x0100;
pub const CKR_KEY_EXTRACTABLE: CK_RV = CKR_VENDOR_DEFINED + 0x0101;
pub const CKR_AUTH_DATA_NOT_ALLOWED: CK_RV = CKR_VENDOR_DEFINED + 0x0102;
pub const CKR_ASSIGNED_KEY_NOT_ALLOWED: CK_RV = CKR_VENDOR_DEFINED + 0x0103;
pub const CKR_INTEGER_OVERFLOW: CK_RV = CKR_VENDOR_DEFINED + 0x0104;
pub const CKR_ECC_CURVE_NOT_ALLOWED: CK_RV = CKR_VENDOR_DEFINED + 0x0105;
pub const CKR_FAILED_TO_CLONE_AN_OBJECT: CK_RV = CKR_VENDOR_DEFINED + 0x0106;
pub const CKR_CLONE_NOT_ATTEMPTED: CK_RV = CKR_VENDOR_DEFINED + 0x0107;
pub const CKR_SESSION_NEGOTIATION_NO_PSK: CK_RV = CKR_VENDOR_DEFINED + 0x0108;
pub const CKR_SESSION_NEGOTIATION_NO_ROOTS: CK_RV = CKR_VENDOR_DEFINED + 0x0109;
pub const CKR_SESSION_NEGOTIATION_NO_ALGS: CK_RV = CKR_VENDOR_DEFINED + 0x010A;
pub const CKR_SESSION_NEGOTIATION_EXPIRED: CK_RV = CKR_VENDOR_DEFINED + 0x010B;
pub const CKR_SESSION_NEGOTIATION_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x010C;
pub const CKR_SESSION_ID_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x010D;
pub const CKR_SESSION_ID_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x010E;
pub const CKR_SESSION_ID_EXPIRED: CK_RV = CKR_VENDOR_DEFINED + 0x010F;
pub const CKR_ATTESTATION_EXPIRED: CK_RV = CKR_VENDOR_DEFINED + 0x0110;
pub const CKR_PROTOCOL_DISABLED: CK_RV = CKR_VENDOR_DEFINED + 0x0111;
pub const CKR_OBJECT_TYPE_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x0112;
pub const CKR_CERTIFICATE_EXPIRED: CK_RV = CKR_VENDOR_DEFINED + 0x0113;
pub const CKR_OBJECT_READ_ONLY: CK_RV = CKR_VENDOR_DEFINED + 0x0114;
pub const CKR_TIME_NOT_INITIALIZED: CK_RV = CKR_VENDOR_DEFINED + 0x0115;
pub const CKR_SESSION_NEGOTIATION_NO_SESSION_DURATION: CK_RV = CKR_VENDOR_DEFINED + 0x0116;
pub const CKR_CPV4_MSG_ERROR: CK_RV = CKR_VENDOR_DEFINED + 0x0117;
pub const CKR_SESSION_NEGOTIATION_NO_KDF: CK_RV = CKR_VENDOR_DEFINED + 0x0118;
pub const CKR_SESSION_NEGOTIATION_NO_ENCODING: CK_RV = CKR_VENDOR_DEFINED + 0x0119;
pub const CKR_SESSION_NEGOTIATION_NO_CHAIN_ATT: CK_RV = CKR_VENDOR_DEFINED + 0x011A;
pub const CKR_SESSION_NEGOTIATION_NO_EPHEMERAL_KEY: CK_RV = CKR_VENDOR_DEFINED + 0x011B;
pub const CKR_DOMAIN_MANAGEMENT_NOT_ALLOWED: CK_RV = CKR_VENDOR_DEFINED + 0x011C;
pub const CKR_DOMAIN_LABEL_INVALID: CK_RV = CKR_VENDOR_DEFINED + 0x011D;
pub const CKR_DOMAIN_LABEL_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x011E;
pub const CKR_DOMAIN_MAX_REACHED: CK_RV = CKR_VENDOR_DEFINED + 0x011F;
pub const CKR_DOMAIN_NO_PRIMARY: CK_RV = CKR_VENDOR_DEFINED + 0x0120;
pub const CKR_DOMAIN_EXTRA_PRIMARY: CK_RV = CKR_VENDOR_DEFINED + 0x0121;
pub const CKR_SESSION_NEGOTIATION_NO_ATTESTATION: CK_RV = CKR_VENDOR_DEFINED + 0x0122;
pub const CKR_SESSION_NEGOTIATION_NOT_STARTED: CK_RV = CKR_VENDOR_DEFINED + 0x0123;
pub const CKR_CLOCK_NOT_IN_SYNC: CK_RV = CKR_VENDOR_DEFINED + 0x0124;
pub const CKR_KEY_NOT_ACTIVE: CK_RV = CKR_VENDOR_DEFINED + 0x136;
pub const CKR_OPERATION_CANCEL_FAILED: CK_RV = CKR_VENDOR_DEFINED + 0x202;
pub const CKR_IS6_GROUP_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x300;
pub const CKR_IS6_MEMBER_OUID_MISMATCH: CK_RV = CKR_VENDOR_DEFINED + 0x301;
pub const CKR_IS6_MEMBER_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x302;
pub const CKR_IS6_MEMBER_DATA_MISSING: CK_RV = CKR_VENDOR_DEFINED + 0x303;
pub const CKR_IS6_DOMAIN_PARM_ALREADY_EXISTS: CK_RV = CKR_VENDOR_DEFINED + 0x304;
pub const CKR_OBJECT_NOT_KEYRING: CK_RV = CKR_VENDOR_DEFINED + 0x305;
pub const CKR_KEYRING_NOT_FOUND: CK_RV = CKR_VENDOR_DEFINED + 0x306;
pub const CKR_KEYRING_NOT_AUTHORIZED: CK_RV = CKR_VENDOR_DEFINED + 0x307;
