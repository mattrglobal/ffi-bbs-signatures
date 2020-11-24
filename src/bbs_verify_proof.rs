use crate::{BbsFfiError, ByteArray, SignatureProofStatus};
use bbs::prelude::*;
use ffi_support::*;
use serde::{
    de::{Error as DError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::TryFrom,
};

lazy_static! {
    static ref VERIFY_PROOF_CONTEXT: ConcurrentHandleMap<VerifyProofContext> =
        ConcurrentHandleMap::new();
}

define_handle_map_deleter!(VERIFY_PROOF_CONTEXT, free_verify_proof);

struct VerifyProofContext {
    messages: BTreeMap<usize, SignatureMessage>,
    nonce: Option<ProofNonce>,
    proof: Option<PoKOfSignatureProofWrapper>,
    public_key: Option<PublicKey>,
}

#[derive(Debug)]
struct PoKOfSignatureProofWrapper {
    bit_vector: Vec<u8>,
    proof: PoKOfSignatureProof,
}

impl TryFrom<&[u8]> for PoKOfSignatureProofWrapper {
    type Error = BBSError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let message_count = u16::from_be_bytes(*array_ref![value, 0, 2]) as usize;
        let bitvector_length = (message_count / 8) + 1;
        let offset = bitvector_length + 2;
        std::fs::write("/tmp/verify_proof.log", base64::encode( &value[offset..])).unwrap();
        let proof = PoKOfSignatureProof::try_from(&value[offset..])?;
        Ok(Self {
            bit_vector: value[..offset].to_vec(),
            proof,
        })
    }
}

impl TryFrom<Vec<u8>> for PoKOfSignatureProofWrapper {
    type Error = BBSError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl PoKOfSignatureProofWrapper {
    pub fn unpack(&self) -> (BTreeSet<usize>, PoKOfSignatureProof) {
        let message_count = u16::from_be_bytes(*array_ref![self.bit_vector, 0, 2]) as usize;
        let bitvector_length = (message_count / 8) + 1;
        let offset = bitvector_length + 2;
        (
            bitvector_to_revealed(&self.bit_vector[2..offset]),
            self.proof.clone(),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = self.bit_vector.to_vec();
        data.append(&mut self.proof.to_bytes_compressed_form());
        data
    }
}

impl Serialize for PoKOfSignatureProofWrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes().as_slice())
    }
}

impl<'a> Deserialize<'a> for PoKOfSignatureProofWrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        struct DeserializeVisitor;

        impl<'a> Visitor<'a> for DeserializeVisitor {
            type Value = PoKOfSignatureProofWrapper;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expected byte array")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<PoKOfSignatureProofWrapper, E>
            where
                E: DError,
            {
                PoKOfSignatureProofWrapper::try_from(value)
                    .map_err(|_| DError::invalid_value(serde::de::Unexpected::Bytes(value), &self))
            }
        }

        deserializer.deserialize_bytes(DeserializeVisitor)
    }
}

#[no_mangle]
pub extern "C" fn bbs_verify_proof_context_init(err: &mut ExternError) -> u64 {
    VERIFY_PROOF_CONTEXT.insert_with_output(err, || VerifyProofContext {
        messages: BTreeMap::new(),
        nonce: None,
        public_key: None,
        proof: None,
    })
}

add_message_impl!(
    bbs_verify_proof_context_add_message_string,
    bbs_verify_proof_context_add_message_bytes,
    bbs_verify_proof_context_add_message_prehashed,
    VERIFY_PROOF_CONTEXT,
    u32
);

add_bytes_impl!(
    bbs_verify_proof_context_set_proof,
    VERIFY_PROOF_CONTEXT,
    proof,
    PoKOfSignatureProofWrapper
);

add_bytes_impl!(
    bbs_verify_proof_context_set_public_key,
    VERIFY_PROOF_CONTEXT,
    public_key,
    PublicKey
);

add_bytes_impl!(
    bbs_verify_proof_context_set_nonce_string,
    bbs_verify_proof_context_set_nonce_bytes,
    bbs_verify_proof_context_set_nonce_prehashed,
    VERIFY_PROOF_CONTEXT,
    nonce,
    ProofNonce
);

#[no_mangle]
pub extern "C" fn bbs_verify_proof_context_finish(handle: u64, err: &mut ExternError) -> i32 {
    let res = VERIFY_PROOF_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<i32, BbsFfiError> {
            if ctx.proof.is_none() {
                Err(BbsFfiError::new("Proof must be set"))?;
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
            let public_key = &ctx.public_key.as_ref().unwrap();
            let nonce = &ctx.nonce.as_ref().unwrap();
            let proofwrapper = ctx.proof.as_ref().unwrap();

            let (revealed, proof) = proofwrapper.unpack();
            let passed_revealed: BTreeSet<usize> = ctx.messages.iter().map(|(k, _)| *k).collect();

            // These should be equal
            if revealed != passed_revealed {
                Err(BbsFfiError::new("Indices are not equal"))?;
            }

            let mut challenge_bytes = proof.get_bytes_for_challenge(revealed.clone(), public_key);
            challenge_bytes.extend_from_slice(&nonce.to_bytes_compressed_form()[..]);

            let challenge_verifier = ProofChallenge::hash(&challenge_bytes);
            let res = proof.verify(public_key, &ctx.messages, &challenge_verifier)?;
            Ok(SignatureProofStatus::from(res) as i32)
        },
    );

    if err.get_code().is_success() {
        match VERIFY_PROOF_CONTEXT.remove_u64(handle) {
            Err(e) => *err = ExternError::new_error(ErrorCode::new(1), format!("{:?}", e)),
            Ok(_) => {}
        };
        res
    } else {
        err.get_code().code()
    }
}
/// Convert big-endian vector to u32
fn bitvector_to_revealed(data: &[u8]) -> BTreeSet<usize> {
    let mut revealed_messages = BTreeSet::new();
    let mut scalar = 0;

    for b in data.iter().rev() {
        let mut v = *b;
        let mut remaining = 8;
        while v > 0 {
            let revealed = v & 1u8;
            if revealed == 1 {
                revealed_messages.insert(scalar);
            }
            v >>= 1;
            scalar += 1;
            remaining -= 1;
        }
        scalar += remaining;
    }
    revealed_messages
}
