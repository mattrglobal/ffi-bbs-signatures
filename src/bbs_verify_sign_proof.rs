use crate::{BbsFfiError, ByteArray, SignatureProofStatus};
use bbs::prelude::*;
use ffi_support::*;
use std::{collections::BTreeSet, convert::TryFrom};

lazy_static! {
    static ref VERIFY_SIGN_PROOF_CONTEXT: ConcurrentHandleMap<VerifyBlindSignProofContext> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(VERIFY_SIGN_PROOF_CONTEXT, free_verify_sign_proof);

struct VerifyBlindSignProofContext {
    blinded: BTreeSet<usize>,
    challenge_hash: Option<ProofChallenge>,
    commitment: Option<Commitment>,
    nonce: Option<ProofNonce>,
    proof: Option<ProofG1>,
    public_key: Option<PublicKey>,
}

#[no_mangle]
pub extern "C" fn bbs_verify_blind_commitment_context_init(err: &mut ExternError) -> u64 {
    VERIFY_SIGN_PROOF_CONTEXT.insert_with_output(err, || VerifyBlindSignProofContext {
        blinded: BTreeSet::new(),
        challenge_hash: None,
        commitment: None,
        nonce: None,
        proof: None,
        public_key: None,
    })
}

#[no_mangle]
pub extern "C" fn bbs_verify_blind_commitment_context_add_blinded(
    handle: u64,
    index: u32,
    err: &mut ExternError,
) -> i32 {
    VERIFY_SIGN_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.blinded.insert(index as usize);
    });
    err.get_code().code()
}

add_bytes_impl!(
    bbs_verify_blind_commitment_context_set_commitment,
    VERIFY_SIGN_PROOF_CONTEXT,
    commitment,
    Commitment
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_set_challenge_hash,
    VERIFY_SIGN_PROOF_CONTEXT,
    challenge_hash,
    ProofChallenge
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_set_public_key,
    VERIFY_SIGN_PROOF_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_set_nonce_string,
    bbs_verify_blind_commitment_context_set_nonce_bytes,
    bbs_verify_blind_commitment_context_set_nonce_prehashed,
    VERIFY_SIGN_PROOF_CONTEXT,
    nonce,
    ProofNonce
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_set_proof,
    VERIFY_SIGN_PROOF_CONTEXT,
    proof,
    ProofG1
);

#[no_mangle]
pub extern "C" fn bbs_verify_blind_commitment_context_finish(handle: u64, err: &mut ExternError) -> i32 {
    let res = VERIFY_SIGN_PROOF_CONTEXT.call_with_result(err, handle, move |ctx| -> Result<i32, BbsFfiError> {
        if ctx.blinded.is_empty() {
            Err(BbsFfiError::new("Blinded indices cannot be empty"))?;
        }
        if ctx.commitment.is_none() {
            Err(BbsFfiError::new("Commitment must be set."))?;
        }
        if ctx.challenge_hash.is_none() {
            Err(BbsFfiError::new("Challenge Hash must be set."))?;
        }
        if ctx.nonce.is_none() {
            Err(BbsFfiError::new("Nonce must be set."))?;
        }
        if ctx.proof.is_none() {
            Err(BbsFfiError::new("Proof must be set."))?;
        }
        if ctx.public_key.is_none() {
            Err(BbsFfiError::new("Public Key must be set"))?;
        }

        let commitment = ctx.commitment.as_ref().unwrap();
        let challenge_hash = ctx.challenge_hash.as_ref().unwrap();
        let nonce = ctx.nonce.as_ref().unwrap();
        let proof = ctx.proof.as_ref().unwrap();
        let public_key = ctx.public_key.as_ref().unwrap();

        let ctx_verify = BlindSignatureContext {
            commitment: commitment.clone(),
            challenge_hash: challenge_hash.clone(),
            proof_of_hidden_messages: proof.clone(),
        };
        if ctx_verify.verify(&ctx.blinded, public_key, nonce)? {
            Ok(SignatureProofStatus::Success as i32)
        } else {
            Ok(SignatureProofStatus::BadHiddenMessage as i32)
        }
    });

    if err.get_code().is_success() {
        match VERIFY_SIGN_PROOF_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
        res
    } else {
        err.get_code().code()
    }
}

