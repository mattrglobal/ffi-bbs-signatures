use crate::{BbsFfiError, ByteArray, ProofMessageType};
use bbs::prelude::*;
use ffi_support::*;
use std::{collections::BTreeSet, convert::TryFrom};

lazy_static! {
    static ref CREATE_PROOF_CONTEXT: ConcurrentHandleMap<CreateProofContext> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(CREATE_PROOF_CONTEXT, free_create_proof);

struct CreateProofContext {
    signature: Option<Signature>,
    public_key: Option<PublicKey>,
    messages: Vec<ProofMessage>,
    nonce: Option<ProofNonce>,
}

struct USize(usize);

unsafe impl IntoFfi for USize {
    type Value = usize;

    fn ffi_default() -> Self::Value {
        0
    }

    fn into_ffi_value(self) -> Self::Value {
        self.0
    }
}

#[no_mangle]
pub extern "C" fn bbs_create_proof_context_size(handle: u64) -> i32 {
    const OVERHEAD: usize = 5 * G1_COMPRESSED_SIZE + 3 * 4 + 4 * FR_COMPRESSED_SIZE + 2;
    let mut err = ExternError::success();
    let res = CREATE_PROOF_CONTEXT.call_with_output(&mut err, handle, |ctx| -> USize {
        USize(32 * ctx.messages.iter().filter(|m| {
           matches!(m, ProofMessage::Hidden(..))
        }).count() + ((ctx.messages.len() / 8) + 1))
    });
    (OVERHEAD + res) as i32
}

#[no_mangle]
pub extern "C" fn bbs_create_proof_context_init(err: &mut ExternError) -> u64 {
    CREATE_PROOF_CONTEXT.insert_with_output(err, || CreateProofContext {
        signature: None,
        messages: Vec::new(),
        public_key: None,
        nonce: None,
    })
}

add_proof_message_impl!(
    bbs_create_proof_context_add_proof_message_string,
    bbs_create_proof_context_add_proof_message_bytes,
    bbs_create_proof_context_add_proof_message_prehashed,
    CREATE_PROOF_CONTEXT
);

add_bytes_impl!(
    bbs_create_proof_context_set_signature,
    CREATE_PROOF_CONTEXT,
    signature,
    Signature
);

add_bytes_impl!(
    bbs_create_proof_context_set_public_key,
    CREATE_PROOF_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_create_proof_context_set_nonce_string,
    bbs_create_proof_context_set_nonce_bytes,
    bbs_create_proof_context_set_nonce_prehashed,
    CREATE_PROOF_CONTEXT,
    nonce,
    ProofNonce
);

#[no_mangle]
pub extern "C" fn bbs_create_proof_context_finish(
    handle: u64,
    proof: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let res = CREATE_PROOF_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, BbsFfiError> {
            if ctx.signature.is_none() {
                Err(BbsFfiError::new("Signature must be set"))?;
            }
            if ctx.public_key.is_none() {
                Err(BbsFfiError::new("Public key must be set"))?;
            }
            if ctx.nonce.is_none() {
                Err(BbsFfiError::new("Nonce must be set"))?;
            }
            if ctx.messages.is_empty() {
                Err(BbsFfiError::new("Messages cannot be empty"))?;
            }
            let signature = ctx.signature.as_ref().unwrap();
            let public_key = &ctx.public_key.as_ref().unwrap();
            let nonce = &ctx.nonce.as_ref().unwrap();

            let pok = PoKOfSignature::init(signature, public_key, &ctx.messages.as_slice())?;
            let mut challenge_bytes = pok.to_bytes();
            challenge_bytes.extend_from_slice(&nonce.to_bytes_compressed_form()[..]);
            let challenge_hash = ProofChallenge::hash(&challenge_bytes);

            let revealed = ctx
                .messages
                .iter()
                .enumerate()
                .filter(|(_, m)| match m {
                    ProofMessage::Revealed(_) => true,
                    _ => false,
                })
                .map(|(i, _)| i)
                .collect();

            let mut bitvector = (ctx.messages.len() as u16).to_be_bytes().to_vec();
            bitvector.append(&mut revealed_to_bitvector(ctx.messages.len(), &revealed));
            let proof = pok.gen_proof(&challenge_hash)?;
            bitvector.append(&mut proof.to_bytes_compressed_form());

            Ok(ByteBuffer::from_vec(bitvector))
        },
    );

    if err.get_code().is_success() {
        *proof = res;
        match CREATE_PROOF_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
    }
    err.get_code().code()
}

/// Expects `revealed` to be sorted
fn revealed_to_bitvector(total: usize, revealed: &BTreeSet<usize>) -> Vec<u8> {
    let mut bytes = vec![0u8; (total / 8) + 1];

    for r in revealed {
        let idx = *r / 8;
        let bit = (*r % 8) as u8;
        bytes[idx] |= 1u8 << bit;
    }

    // Convert to big endian
    bytes.reverse();
    bytes
}
