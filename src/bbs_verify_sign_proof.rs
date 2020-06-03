use crate::{BbsFfiError, ByteArray};
use bbs::prelude::*;
use ffi_support::*;
use std::{
    collections::BTreeSet,
    convert::TryFrom
};

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
pub extern "C" fn bbs_verify_blind_commitment_context_add_blinded(handle: u64, index: u32, err: &mut ExternError) -> i32 {
    VERIFY_SIGN_PROOF_CONTEXT.call_with_output_mut(err, handle, |ctx| {
        ctx.blinded.insert(index as usize);
    });
    err.get_code().code()
}

add_bytes_impl!(
    bbs_verify_blind_commitment_context_add_commitment,
    VERIFY_SIGN_PROOF_CONTEXT,
    commitment,
    Commitment
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_add_challenge_hash,
    VERIFY_SIGN_PROOF_CONTEXT,
    challenge_hash,
    ProofChallenge
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_add_public_key,
    VERIFY_SIGN_PROOF_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_add_nonce,
    VERIFY_SIGN_PROOF_CONTEXT,
    nonce,
    ProofNonce
);

add_bytes_impl!(
    bbs_verify_blind_commitment_context_add_proof,
    VERIFY_SIGN_PROOF_CONTEXT,
    proof,
    ProofG1
);