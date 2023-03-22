#[macro_use]
extern crate arrayref;
#[macro_use]
extern crate ffi_support;
#[macro_use]
extern crate lazy_static;

use bbs::errors::BBSError;
use bbs::pok_vc::PoKVCError;
use ffi_support::{ByteBuffer, ErrorCode, ExternError};

use pairing_plus::{
    bls12_381::{Bls12, Fr, G1, G2},
    hash_to_field::BaseFromRO,
    serdes::SerDes,
    CurveProjective,
};
use rand::prelude::*;
use std::{ptr, slice};

/// Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
/// If Rust allocated, then the outgoing struct is `ffi_support::ByteBuffer`
/// Caller is responsible for calling free where applicable.
///
/// C will not notice a difference and can use the same struct
#[repr(C)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> Self {
        Self {
            length: 0,
            data: ptr::null(),
        }
    }
}

impl ByteArray {
    /// Convert this into a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }

    /// Convert this into a byte vector if possible
    /// Some if success
    /// None if not
    pub fn to_opt_vec(&self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            None
        } else if self.length == 0 {
            Some(Vec::new())
        } else {
            Some(unsafe { slice::from_raw_parts(self.data, self.length).to_vec() })
        }
    }

    ///Convert to outgoing struct ByteBuffer
    pub fn into_byte_buffer(self) -> ByteBuffer {
        ByteBuffer::from_vec(self.to_vec())
    }

    /// Convert a slice to ByteArray
    pub fn from_slice<I: AsRef<[u8]>>(data: I) -> Self {
        let data = data.as_ref();
        Self {
            length: data.len(),
            data: data.as_ptr() as *const u8,
        }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(b: &Vec<u8>) -> Self {
        Self::from_slice(b)
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(b: Vec<u8>) -> Self {
        Self::from_slice(&b)
    }
}

impl From<&[u8]> for ByteArray {
    fn from(b: &[u8]) -> Self {
        Self::from_slice(b)
    }
}

impl From<ByteBuffer> for ByteArray {
    fn from(b: ByteBuffer) -> Self {
        Self::from_slice(&b.destroy_into_vec())
    }
}

#[repr(C)]
#[derive(PartialEq, Eq)]
pub enum ProofMessageType {
    Revealed = 1,
    HiddenProofSpecificBlinding = 2,
    HiddenExternalBlinding = 3,
}

define_string_destructor!(bbs_string_free);
define_bytebuffer_destructor!(bbs_byte_buffer_free);

/// Wrapper to convert a string to ExternError and BBSError
pub(crate) struct BbsFfiError(pub String);

impl BbsFfiError {
    pub fn new(m: &str) -> Self {
        Self(m.to_string())
    }
}

impl From<BbsFfiError> for ExternError {
    fn from(e: BbsFfiError) -> Self {
        ExternError::new_error(ErrorCode::new(1), e.0)
    }
}

impl From<BBSError> for BbsFfiError {
    fn from(e: BBSError) -> Self {
        BbsFfiError(format!("{:?}", e))
    }
}

impl From<PoKVCError> for BbsFfiError {
    fn from(e: PoKVCError) -> Self {
        BbsFfiError(format!("{:?}", e))
    }
}

const BLINDING_G1: &[u8] = &[
    185, 201, 5, 142, 138, 68, 184, 112, 20, 249, 139, 228, 225, 129, 141, 183, 24, 248, 178, 213,
    16, 31, 200, 158, 105, 131, 98, 95, 50, 31, 20, 184, 77, 124, 246, 225, 85, 0, 73, 135, 162,
    21, 238, 66, 109, 241, 115, 201,
];
const BLINDING_G2: &[u8] = &[
    169, 99, 222, 42, 223, 177, 22, 60, 244, 190, 210, 77, 112, 140, 228, 116, 50, 116, 45, 32,
    128, 178, 87, 62, 190, 46, 25, 168, 105, 143, 96, 197, 65, 206, 192, 0, 252, 177, 151, 131,
    233, 190, 115, 52, 19, 86, 223, 95, 17, 145, 205, 222, 199, 196, 118, 215, 116, 43, 204, 66,
    26, 252, 93, 80, 94, 99, 55, 60, 98, 126, 160, 31, 218, 4, 240, 228, 1, 89, 210, 91, 221, 18,
    244, 90, 1, 13, 133, 128, 167, 143, 106, 125, 38, 34, 114, 243,
];

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g2` ^ `x` * `blinding_g2` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g2_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (r, pk, sk) = bls_generate_keypair::<G2>(ikm, Some(BLINDING_G2));
    (r.unwrap(), pk, sk)
}

/// Generate a blinded BLS key pair where secret key `x` and blinding factor `r` in Fp
/// and public key `w` = `g1` ^ `x` * `blinding_g1` ^ `r`
/// `seed`: `ArrayBuffer` [opt]
/// `return` Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer`, blindingFactor: `ArrayBuffer` }
fn bls_generate_blinded_g1_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (r, pk, sk) = bls_generate_keypair::<G1>(ikm, Some(BLINDING_G1));
    (r.unwrap(), pk, sk)
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g2` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g2_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let (_, pk, sk) = bls_generate_keypair::<G2>(ikm, None);
    (pk, sk)
}

/// Generate a BLS key pair where secret key `x` in Fp
/// and public key `w` = `g1` ^ `x`
/// `seed`: `ArrayBuffer` [opt]
/// `return`: Object { publicKey: `ArrayBuffer`, secretKey: `ArrayBuffer` }
fn bls_generate_g1_key(ikm: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let (_, pk, sk) = bls_generate_keypair::<G1>(ikm, None);
    (pk, sk)
}

fn bls_generate_keypair<G: CurveProjective<Engine = Bls12, Scalar = Fr> + SerDes>(
    ikm: Option<Vec<u8>>,
    blinded: Option<&[u8]>,
) -> (Option<Vec<u8>>, Vec<u8>, Vec<u8>) {
    let passed_seed = ikm.is_some();
    let seed = ikm.unwrap_or_else(|| {
        let mut rng = thread_rng();
        let mut seed_data = vec![0u8, 32];
        rng.fill_bytes(seed_data.as_mut_slice());
        seed_data
    });

    let sk = gen_sk(seed.as_slice());
    let mut pk = G::one();
    pk.mul_assign(sk);

    let r = match blinded {
        Some(g) => {
            let mut data = g.to_vec();
            let mut gg = g;
            if passed_seed {
                data.extend_from_slice(seed.as_slice());
            } else {
                let mut rng = thread_rng();
                let mut blinding_factor = vec![0u8, 32];
                rng.fill_bytes(blinding_factor.as_mut_slice());
                data.extend_from_slice(blinding_factor.as_slice());
            }
            let mut blinding_g = G::deserialize(&mut gg, true).unwrap();
            let r = gen_sk(data.as_slice());
            blinding_g.mul_assign(r);
            pk.add_assign(&blinding_g);
            let mut r_bytes = Vec::new();
            r.serialize(&mut r_bytes, true).unwrap();
            Some(r_bytes)
        }
        None => None,
    };

    let mut sk_bytes = Vec::new();
    let mut pk_bytes = Vec::new();
    sk.serialize(&mut sk_bytes, true).unwrap();
    pk.serialize(&mut pk_bytes, true).unwrap();

    (r, pk_bytes, sk_bytes)
}

fn gen_sk(msg: &[u8]) -> Fr {
    use sha2::digest::generic_array::{typenum::U48, GenericArray};
    const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
    // copy of `msg` with appended zero byte
    let mut msg_prime = Vec::<u8>::with_capacity(msg.as_ref().len() + 1);
    msg_prime.extend_from_slice(msg.as_ref());
    msg_prime.extend_from_slice(&[0]);
    // `result` has enough length to hold the output from HKDF expansion
    let mut result = GenericArray::<u8, U48>::default();
    assert!(hkdf::Hkdf::<sha2::Sha256>::new(Some(SALT), &msg_prime[..])
        .expand(&[0, 48], &mut result)
        .is_ok());
    Fr::from_okm(&result)
}

#[macro_use]
mod macros;
pub mod bbs_blind_commitment;
pub mod bbs_blind_sign;
pub mod bbs_create_proof;
pub mod bbs_sign;
pub mod bbs_verify_proof;
pub mod bbs_verify_sign_proof;
pub mod bls;

#[cfg(any(target_os = "linux", feature = "java"))]
pub mod java;
