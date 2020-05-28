use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, FfiStr};
use std::io::BufRead;
use std::{collections::BTreeMap, convert::TryFrom};

lazy_static! {
    static ref BLIND_SIGN_CONTEXTS: ConcurrentHandleMap<BbsBlindSignContext> = ConcurrentHandleMap::new();
}

define_handle_map_deleter!(BLIND_SIGN_CONTEXTS, free_bbs_blind_sign);

struct BbsBlindSignContext {
    pub messages: BTreeMap<usize, SignatureMessage>,
    pub public_key: Option<PublicKey>,
    pub nonce: Option<ProofNonce>,
}

#[no_mangle]
pub extern "C" fn bbs_blind_signature_size() -> i32 {
    SIGNATURE_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_init(err: &mut ExternError) -> u64 {
    BLIND_SIGN_CONTEXTS.insert_with_output(err, || BbsBlindSignContext {
        messages: BTreeMap::new(),
        public_key: None,
        nonce: None,
    })
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_add_message_string(
    handle: u64,
    index: u32,
    message: FfiStr<'_>,
    err: &mut ExternError,
) -> i32 {
    let message = message.into_string();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    BLIND_SIGN_CONTEXTS.call_with_output_mut(err, handle, |ctx| {
        ctx.messages
            .insert(index as usize, SignatureMessage::hash(message.as_bytes()));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_add_message_bytes(
    handle: u64,
    index: u32,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    BLIND_SIGN_CONTEXTS.call_with_output_mut(err, handle, |ctx| {
        ctx.messages
            .insert(index as usize, SignatureMessage::hash(&message));
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_add_message_prehashed(
    handle: u64,
    index: u32,
    message: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let message = message.to_vec();
    if message.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
        return 1;
    }
    BLIND_SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let msg =
            SignatureMessage::try_from(message).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.messages.insert(index as usize, msg);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_add_public_key(
    handle: u64,
    public_key: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let public_key = public_key.to_vec();
    if public_key.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Public Key cannot be empty");
        return 1;
    }
    BLIND_SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let key = PublicKey::try_from(public_key).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.public_key = Some(key);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_add_nonce(
    handle: u64,
    nonce: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let nonce = nonce.to_vec();
    if nonce.is_empty() {
        *err = ExternError::new_error(ErrorCode::new(1), "Nonce cannot be empty");
        return 1;
    }
    BLIND_SIGN_CONTEXTS.call_with_result_mut(err, handle, |ctx| -> Result<(), BbsFfiError> {
        let key = ProofNonce::try_from(nonce).map_err(|e| BbsFfiError(format!("{:?}", e)))?;
        ctx.nonce = Some(key);
        Ok(())
    });
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_finish(
    handle: u64,
    out_context: &mut ByteBuffer,
    blinding_factor: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let res = BLIND_SIGN_CONTEXTS.call_with_result(
        err,
        handle,
        move |ctx| -> Result<(ByteBuffer, ByteBuffer), BbsFfiError> {
            if ctx.nonce.is_none() {
                Err(BbsFfiError::new("Nonce must be set"))?;
            }
            if ctx.public_key.is_none() {
                Err(BbsFfiError::new("Public Key must be set"))?;
            }
            if ctx.messages.is_empty() {
                Err(BbsFfiError::new("Messages cannot be empty"))?;
            }

            match (ctx.nonce.as_ref(), ctx.public_key.as_ref()) {
                (Some(ref n), Some(ref pk)) => {
                    let (c, b) = Prover::new_blind_signature_context(pk, &ctx.messages, n)
                        .map_err(|e| BbsFfiError(format!("{:?}", e)))?;
                    Ok((
                        ByteBuffer::from_vec(c.to_bytes_compressed_form().to_vec()),
                        ByteBuffer::from_vec(b.to_bytes_compressed_form().to_vec()),
                    ))
                }
                (_, _) => Ok((ByteBuffer::new_with_size(0), ByteBuffer::new_with_size(0))),
            }
        },
    );

    if err.get_code().is_success() {
        let (c, b) = res.unwrap();
        *out_context = c;
        *blinding_factor = b;
        match BLIND_SIGN_CONTEXTS.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
    }
    err.get_code().code()
}
