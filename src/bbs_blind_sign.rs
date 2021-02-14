use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::{
    call_with_result, ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, FfiStr,
};
use std::{collections::BTreeMap, convert::TryFrom};

lazy_static! {
    static ref BLIND_SIGN_CONTEXT: ConcurrentHandleMap<BlindSignContext> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(BLIND_SIGN_CONTEXT, free_bbs_blind_sign);

struct BlindSignContext {
    commitment: Option<Commitment>,
    messages: BTreeMap<usize, SignatureMessage>,
    public_key: Option<PublicKey>,
    secret_key: Option<SecretKey>,
}

#[no_mangle]
pub extern "C" fn bbs_blinding_factor_size() -> i32 {
    FR_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_init(err: &mut ExternError) -> u64 {
    BLIND_SIGN_CONTEXT.insert_with_output(err, || BlindSignContext {
        commitment: None,
        messages: BTreeMap::new(),
        public_key: None,
        secret_key: None,
    })
}

add_message_impl!(
    bbs_blind_sign_context_add_message_string,
    bbs_blind_sign_context_add_message_bytes,
    bbs_blind_sign_context_add_message_prehashed,
    BLIND_SIGN_CONTEXT,
    u32
);

add_bytes_impl!(
    bbs_blind_sign_context_set_public_key,
    BLIND_SIGN_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_blind_sign_context_set_secret_key,
    BLIND_SIGN_CONTEXT,
    secret_key,
    SecretKey
);

add_bytes_impl!(
    bbs_blind_sign_context_set_commitment,
    BLIND_SIGN_CONTEXT,
    commitment,
    Commitment
);

#[no_mangle]
pub extern "C" fn bbs_blind_sign_context_finish(
    handle: u64,
    blinded_signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let res = BLIND_SIGN_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, BbsFfiError> {
            if ctx.commitment.is_none() {
                Err(BbsFfiError::new("Commitment must be set"))?;
            }
            if ctx.secret_key.is_none() {
                Err(BbsFfiError::new("Secret Key must be set"))?;
            }
            if ctx.public_key.is_none() {
                Err(BbsFfiError::new("Public Key must be set"))?;
            }
            if ctx.messages.is_empty() {
                Err(BbsFfiError::new("Messages cannot be empty"))?;
            }
            let commitment = ctx.commitment.as_ref().unwrap();
            let sk = ctx.secret_key.as_ref().unwrap();
            let pk = ctx.public_key.as_ref().unwrap();
            let sig = BlindSignature::new(&commitment, &ctx.messages, &sk, &pk)?;
            Ok(ByteBuffer::from_vec(
                sig.to_bytes_compressed_form().to_vec(),
            ))
        },
    );

    if err.get_code().is_success() {
        *blinded_signature = res;
        match BLIND_SIGN_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
    }
    err.get_code().code()
}

#[no_mangle]
pub extern "C" fn bbs_unblind_signature(
    blind_signature: ByteArray,
    blinding_factor: ByteArray,
    unblind_signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let res = call_with_result(err, || -> Result<ByteBuffer, BbsFfiError> {
        let blinded_sig = BlindSignature::try_from(blind_signature.to_vec())?;
        let bf = SignatureBlinding::try_from(blinding_factor.to_vec())?;
        let sig = blinded_sig.to_unblinded(&bf);
        Ok(ByteBuffer::from_vec(
            sig.to_bytes_compressed_form().to_vec(),
        ))
    });
    *unblind_signature = res;
    0
}
