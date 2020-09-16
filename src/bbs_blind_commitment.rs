use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::{ByteBuffer, ConcurrentHandleMap, ErrorCode, ExternError, FfiStr};
use std::{collections::BTreeMap, convert::TryFrom};

lazy_static! {
    static ref BLIND_COMMITMENT_CONTEXT: ConcurrentHandleMap<BlindCommitmentContext> =
        ConcurrentHandleMap::new();
    // static ref VERIFY_SIGN_PROOF_CONTEXT: ConcurrentHandleMap<VerifyBlindSignProofContext> =
    //     ConcurrentHandleMap::new();
}

define_handle_map_deleter!(BLIND_COMMITMENT_CONTEXT, free_bbs_blind_commitment);

struct BlindCommitmentContext {
    messages: BTreeMap<usize, SignatureMessage>,
    public_key: Option<PublicKey>,
    nonce: Option<ProofNonce>,
}

#[no_mangle]
pub extern "C" fn bbs_blind_signature_size() -> i32 {
    SIGNATURE_COMPRESSED_SIZE as i32
}

#[no_mangle]
pub extern "C" fn bbs_blind_commitment_context_init(err: &mut ExternError) -> u64 {
    BLIND_COMMITMENT_CONTEXT.insert_with_output(err, || BlindCommitmentContext {
        messages: BTreeMap::new(),
        public_key: None,
        nonce: None,
    })
}

add_message_impl!(
    bbs_blind_commitment_context_add_message_string,
    bbs_blind_commitment_context_add_message_bytes,
    bbs_blind_commitment_context_add_message_prehashed,
    BLIND_COMMITMENT_CONTEXT,
    u32
);

add_bytes_impl!(
    bbs_blind_commitment_context_set_public_key,
    BLIND_COMMITMENT_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_blind_commitment_context_set_nonce_string,
    bbs_blind_commitment_context_set_nonce_bytes,
    bbs_blind_commitment_context_set_nonce_prehashed,
    BLIND_COMMITMENT_CONTEXT,
    nonce,
    ProofNonce
);

#[no_mangle]
pub extern "C" fn bbs_blind_commitment_context_finish(
    handle: u64,
    commitment: &mut ByteBuffer,
    out_context: &mut ByteBuffer,
    blinding_factor: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let res = BLIND_COMMITMENT_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, BbsFfiError> {
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
                    let (c, b) = Prover::new_blind_signature_context(pk, &ctx.messages, n)?;
                    let mut output = Vec::new();
                    output.append(&mut b.to_bytes_compressed_form().to_vec());
                    output.append(&mut c.to_bytes_compressed_form());
                    Ok(ByteBuffer::from_vec(output))
                }
                (_, _) => Ok(ByteBuffer::new_with_size(0)),
            }
        },
    );

    if err.get_code().is_success() {
        let v = res.into_vec();
        *blinding_factor = ByteBuffer::from_vec(v[..FR_COMPRESSED_SIZE].to_vec());
        let commitment_end = G1_COMPRESSED_SIZE + FR_COMPRESSED_SIZE;
        *commitment = ByteBuffer::from_vec(v[FR_COMPRESSED_SIZE..commitment_end].to_vec());
        *out_context = ByteBuffer::from_vec(v[FR_COMPRESSED_SIZE..].to_vec());
        match BLIND_COMMITMENT_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
    }
    err.get_code().code()
}
