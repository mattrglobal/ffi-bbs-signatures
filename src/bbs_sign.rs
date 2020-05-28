use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, FfiStr};
use std::convert::TryFrom;

lazy_static! {
    static ref SIGN_CONTEXTS: ConcurrentHandleMap<BbsSignContext> = ConcurrentHandleMap::new();
}

define_handle_map_deleter!(SIGN_CONTEXTS, free_bbs_sign);

struct BbsSignContext {
    pub messages: Vec<SignatureMessage>,
    pub secret_key: Option<SecretKey>,
    pub public_key: Option<PublicKey>,
    pub signature: Option<Signature>,
}

#[no_mangle]
pub extern "C" fn bbs_signature_size() -> i32 {
    SIGNATURE_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_init(err: &mut ExternError) -> u64 {
    SIGN_CONTEXTS.insert_with_output(err, || BbsSignContext {
        messages: Vec::new(),
        secret_key: None,
        signature: None,
        public_key: None,
    })
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_add_message_string(
    handle: u64,
    message: FfiStr<'_>,
    err: &mut ExternError,
) -> i32 {
    let message = message.into_string();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_output_mut(err, handle, |ctx| {
        ctx.messages
            .push(SignatureMessage::hash(message.as_bytes()));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_add_message_bytes(
    handle: u64,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_output_mut(err, handle, |ctx| {
        ctx.messages.push(SignatureMessage::hash(&message));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_add_message_prehashed(
    handle: u64,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let msg =
            SignatureMessage::try_from(message).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.messages.push(msg);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_add_secret_key(
    handle: u64,
    secret_key: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let secret_key = secret_key.to_vec();
    if secret_key.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Secret Key cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let key = SecretKey::try_from(secret_key).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.secret_key = Some(key);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_add_public_key(
    handle: u64,
    public_key: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let public_key = public_key.to_vec();
    if public_key.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Public Key cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let key = PublicKey::try_from(public_key).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.public_key = Some(key);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_sign_context_finish(
    handle: u64,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let sig = SIGN_CONTEXTS.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, BbsFfiError> {
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
                    let s = Signature::new(ctx.messages.as_slice(), sk, pk)
                        .map_err(|e| BbsFfiError(format!("{:?}", e)))?;
                    Ok(ByteBuffer::from_vec(s.to_bytes_compressed_form().to_vec()))
                }
                (_, _) => Ok(ByteBuffer::new_with_size(0)),
            }
        },
    );

    if err.get_code().is_success() {
        *signature = sig.unwrap();
        match SIGN_CONTEXTS.remove_u64(handle) {
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
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_message_bytes(handle, message, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_message_prehashed(
    handle: u64,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_message_prehashed(handle, message, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_public_key(
    handle: u64,
    public_key: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    bbs_sign_context_add_public_key(handle, public_key, err)
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_add_signature(
    handle: u64,
    signature: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let signature = signature.to_vec();
    if signature.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Signature cannot be empty");
        return 1;
    }
    SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let sig = Signature::try_from(signature).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.signature = Some(sig);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_verify_context_finish(handle: u64, err: &mut ExternError) -> i32 {
    SIGN_CONTEXTS.call_with_result(err, handle, move |ctx| -> Result<i32, BbsFfiError> {
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
                Ok(b) => Ok(if b { 0 } else { 2 }),
                Err(e) => Err(BbsFfiError(format!("{:?}", e))),
            },
            (_, _) => Err(BbsFfiError::new("")),
        }
    });

    err.get_code().code()
}
