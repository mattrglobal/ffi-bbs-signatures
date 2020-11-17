use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, FfiStr};
use std::convert::TryFrom;

lazy_static! {
    static ref SIGN_CONTEXT: ConcurrentHandleMap<SignContext> = ConcurrentHandleMap::new();
}

define_handle_map_deleter!(SIGN_CONTEXT, free_bbs_sign);

struct SignContext {
    messages: Vec<SignatureMessage>,
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    signature: Option<Signature>,
}

#[no_mangle]
pub extern "C" fn bbs_signature_size() -> i32 {
    SIGNATURE_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_init(err: &mut ExternError) -> u64 {
    SIGN_CONTEXT.insert_with_output(err, || SignContext {
        messages: Vec::new(),
        secret_key: None,
        signature: None,
        public_key: None,
    })
}

add_message_impl!(
    bbs_sign_context_add_message_string,
    bbs_sign_context_add_message_bytes,
    bbs_sign_context_add_message_prehashed,
    SIGN_CONTEXT
);

add_bytes_impl!(
    bbs_sign_context_set_secret_key,
    SIGN_CONTEXT,
    secret_key,
    SecretKey
);
add_bytes_impl!(
    bbs_sign_context_set_public_key,
    SIGN_CONTEXT,
    public_key,
    PublicKey
);

#[no_mangle]
pub extern "C" fn bbs_sign_context_finish(
    handle: u64,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sig =
        SIGN_CONTEXT.call_with_result(err, handle, move |ctx| -> Result<ByteBuffer, BbsFfiError> {
            if ctx.secret_key.is_none() {
                Err(BbsFfiError::new("Secret Key must be set"))?;
            }
            if ctx.public_key.is_none() {
                Err(BbsFfiError::new("Public Key must be set"))?;
            }
            if ctx.messages.is_empty() {
                Err(BbsFfiError::new("Messages cannot be empty"))?;
            }

            match (ctx.secret_key.as_ref(), ctx.public_key.as_ref()) {
                (Some(ref sk), Some(ref pk)) => {
                    let s = Signature::new(ctx.messages.as_slice(), sk, pk)?;
                    Ok(ByteBuffer::from_vec(s.to_bytes_compressed_form().to_vec()))
                }
                (_, _) => Ok(ByteBuffer::new_with_size(0)),
            }
        });

    if err.get_code().is_success() {
        *signature = sig;
        match SIGN_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_init(err: &mut ExternError) -> u64 {
    bbs_sign_context_init(err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_message_string(
    handle: u64,
    message: FfiStr<'_>,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_message_string(handle, message, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_message_bytes(
    handle: u64,
    message: ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_message_bytes(handle, message, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_message_prehashed(
    handle: u64,
    message: ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_message_prehashed(handle, message, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_set_public_key(
    handle: u64,
    public_key: ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_set_public_key(handle, public_key, err)
}

add_bytes_impl!(
    bbs_verify_context_set_signature,
    SIGN_CONTEXT,
    signature,
    Signature
);

#[no_mangle]
pub extern "C" fn bbs_verify_context_finish(handle: u64, err: &mut ExternError) -> i32 {
    SIGN_CONTEXT.call_with_result(err, handle, move |ctx| -> Result<i32, BbsFfiError> {
        if ctx.signature.is_none() {
            Err(BbsFfiError::new("Signature must be set"))?;
        }
        if ctx.public_key.is_none() {
            Err(BbsFfiError::new("Public Key must be set"))?;
        }
        if ctx.messages.is_empty() {
            Err(BbsFfiError::new("Messages cannot be empty"))?;
        }

        match (ctx.signature.as_ref(), ctx.public_key.as_ref()) {
            (Some(ref sig), Some(ref pk)) => match sig.verify(ctx.messages.as_slice(), pk) {
                Ok(b) => Ok(if b { 1 } else { 0 }),
                Err(e) => Err(BbsFfiError(format!("{:?}", e))),
            },
            (_, _) => Err(BbsFfiError::new("")),
        }
    })
}
