use crate::ByteArray;
use bbs::prelude::*;
use ffi_support::{ByteBuffer, ErrorCode, ExternError};
use std::convert::TryFrom;

#[no_mangle]
pub extern "C" fn bls_secret_key_size() -> i32 {
    FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bls_public_key_g2_size() -> i32 {
    G2_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn blinding_factor_size() -> i32 {
    FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bls_public_key_g1_size() -> i32 {
    G1_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bls_generate_g2_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let (p, s) = crate::bls_generate_g2_key(seed.to_opt_vec());
    *public_key = ByteBuffer::from_vec(p);
    *secret_key = ByteBuffer::from_vec(s);
    *err = ExternError::success();
    0
}

#[no_mangle]
pub extern "C" fn bls_generate_g1_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let (p, s) = crate::bls_generate_g1_key(seed.to_opt_vec());
    *public_key = ByteBuffer::from_vec(p);
    *secret_key = ByteBuffer::from_vec(s);
    *err = ExternError::success();
    0
}

#[no_mangle]
pub extern "C" fn bls_generate_blinded_g2_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    blinding_factor: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let (p, s, b) = crate::bls_generate_blinded_g2_key(seed.to_opt_vec());
    *public_key = ByteBuffer::from_vec(p);
    *secret_key = ByteBuffer::from_vec(s);
    *blinding_factor = ByteBuffer::from_vec(b);
    *err = ExternError::success();
    0
}

#[no_mangle]
pub extern "C" fn bls_generate_blinded_g1_key(
    seed: ByteArray,
    public_key: &mut ByteBuffer,
    secret_key: &mut ByteBuffer,
    blinding_factor: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let (p, s, b) = crate::bls_generate_blinded_g1_key(seed.to_opt_vec());
    *public_key = ByteBuffer::from_vec(p);
    *secret_key = ByteBuffer::from_vec(s);
    *blinding_factor = ByteBuffer::from_vec(b);
    *err = ExternError::success();
    0
}

#[no_mangle]
pub extern "C" fn bls_get_public_key(
    secret_key: ByteArray,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sk = SecretKey::try_from(secret_key.to_vec());
    match sk {
        Ok(s) => {
            let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(s)));
            *public_key = ByteBuffer::from_vec(dpk.to_bytes_compressed_form().to_vec());
            *err = ExternError::success();
            0
        }
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e));
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn bls_secret_key_to_bbs_key(
    secret_key: ByteArray,
    message_count: u32,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sk = SecretKey::try_from(secret_key.to_vec());
    match sk {
        Ok(s) => {
            let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(s)));
            let res = dpk.to_public_key(message_count as usize);
            match res {
                Ok(pk) => {
                    *public_key = ByteBuffer::from_vec(pk.to_bytes_compressed_form().to_vec());
                    *err = ExternError::success();
                    0
                }
                Err(e) => {
                    *err = ExternError::new_error(ErrorCode::new(2), format!("{:?}", e));
                    2
                }
            }
        }
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e));
            1
        }
    }
}

#[no_mangle]
pub extern "C" fn bls_public_key_to_bbs_key(
    d_public_key: ByteArray,
    message_count: u32,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let bytes = d_public_key.to_vec();
    let res = DeterministicPublicKey::try_from(bytes.clone());
    match res {
        Err(e) => {
            *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}. Found length {} with {:?}", e, bytes.len(), bytes));
            1
        }
        Ok(dpk) => {
            let re = dpk.to_public_key(message_count as usize);
            match re {
                Ok(pk) => {
                    *public_key = ByteBuffer::from_vec(pk.to_bytes_compressed_form().to_vec());
                    *err = ExternError::success();
                    0
                }
                Err(e) => {
                    *err = ExternError::new_error(ErrorCode::new(2), format!("{:?}", e));
                    2
                }
            }
        }
    }
}
