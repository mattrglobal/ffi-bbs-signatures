// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JObject, JString};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jbyte, jbyteArray, jint, jlong};

use crate::bbs_blind_commitment::{
    bbs_blind_commitment_context_add_message_bytes,
    bbs_blind_commitment_context_add_message_prehashed, bbs_blind_commitment_context_finish,
    bbs_blind_commitment_context_init, bbs_blind_commitment_context_set_nonce_bytes,
    bbs_blind_commitment_context_set_public_key, bbs_blind_signature_size,
};
use crate::bbs_blind_sign::{
    bbs_blind_sign_context_add_message_bytes, bbs_blind_sign_context_add_message_prehashed,
    bbs_blind_sign_context_finish, bbs_blind_sign_context_init,
    bbs_blind_sign_context_set_commitment, bbs_blind_sign_context_set_public_key,
    bbs_blind_sign_context_set_secret_key, bbs_blinding_factor_size, bbs_unblind_signature,
};
use crate::bbs_create_proof::{
    CREATE_PROOF_CONTEXT,
    bbs_create_proof_context_add_proof_message_bytes, bbs_create_proof_context_finish,
    bbs_create_proof_context_init, bbs_create_proof_context_set_nonce_bytes,
    bbs_create_proof_context_set_signature,
    bbs_create_proof_context_size,
};
use crate::bbs_sign::*;
use crate::bbs_verify_proof::{
    VERIFY_PROOF_CONTEXT,
    bbs_verify_proof_context_add_message_bytes, bbs_verify_proof_context_add_message_prehashed,
    bbs_verify_proof_context_finish, bbs_verify_proof_context_init,
    bbs_verify_proof_context_set_nonce_bytes, bbs_verify_proof_context_set_proof,
};
use crate::bls::{bls_public_key_g1_size, bls_public_key_g2_size, bls_secret_key_size};
use crate::*;
use crate::{
    bls_generate_blinded_g1_key, bls_generate_blinded_g2_key, bls_generate_g1_key,
    bls_generate_g2_key,
};
use bbs::keys::{DeterministicPublicKey, KeyGenOption, SecretKey, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE, PublicKey};
use bbs::{ToVariableLengthBytes, FR_COMPRESSED_SIZE, G1_COMPRESSED_SIZE};

use std::cell::RefCell;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = RefCell::new(None);
}

fn update_last_error(m: &str) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(m.to_string());
    })
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_get_1last_1error<'a>(env: JNIEnv<'a>, _: JObject) -> JString<'a> {
    let mut res = env.new_string("").unwrap();
    LAST_ERROR.with(|prev| {
        match &*prev.borrow() {
            Some(s) => res = env.new_string(s).unwrap(),
            None => ()
        };
    });
    res
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g1_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
    bls_public_key_g1_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1public_1key_1g2_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
    bls_public_key_g2_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_blinding_1factor_1size(_: JNIEnv, _: JObject) -> jint {
    bbs_blinding_factor_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1secret_1key_1size(_: JNIEnv, _: JObject) -> jint {
    bls_secret_key_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1signature_1size(_: JNIEnv, _: JObject) -> jint {
    bbs_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1signature_1size(
    _: JNIEnv,
    _: JObject,
) -> jint {
    bbs_blind_signature_size()
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1generate_1g1_1key(
    env: JNIEnv,
    _: JObject,
    seed: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 1,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (pk_bytes, sk_bytes) = bls_generate_g1_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1generate_1g2_1key(
    env: JNIEnv,
    _: JObject,
    seed: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 1,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (pk_bytes, sk_bytes) = bls_generate_g2_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1generate_1blinded_1g1_1key(
    env: JNIEnv,
    _: JObject,
    seed: jbyteArray,
    bf: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 1,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (r_bytes, pk_bytes, sk_bytes) = bls_generate_blinded_g1_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    let r: Vec<i8> = r_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    copy_to_jni!(env, bf, r.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1generate_1blinded_1g2_1key(
    env: JNIEnv,
    _: JObject,
    seed: jbyteArray,
    bf: jbyteArray,
    public_key: jbyteArray,
    secret_key: jbyteArray,
) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 1,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (r_bytes, pk_bytes, sk_bytes) = bls_generate_blinded_g2_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    let r: Vec<i8> = r_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    copy_to_jni!(env, bf, r.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1secret_1key_1to_1bbs_1key(
    env: JNIEnv,
    _: JObject,
    secret_key: jbyteArray,
    message_count: jint,
) -> jbyteArray {
    let bad_res = env.new_byte_array(0).unwrap();
    let sk = get_secret_key(&env, secret_key);
    if sk.is_err() {
        return bad_res;
    }
    let sk = sk.unwrap();
    let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
    let pk;
    match dpk.to_public_key(message_count as usize) {
        Err(_) => return bad_res,
        Ok(p) => pk = p,
    };
    if pk.validate().is_err() {
        return bad_res;
    }

    let pk_bytes = pk.to_bytes_compressed_form();
    match env.new_byte_array(pk_bytes.len() as jint) {
        Err(_) => bad_res,
        Ok(out) => {
            let pp: Vec<jbyte> = pk_bytes.iter().map(|b| *b as jbyte).collect();
            copy_to_jni!(env, out, pp.as_slice(), bad_res);
            out
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bls_1public_1key_1to_1bbs_1key(
    env: JNIEnv,
    _: JObject,
    short_public_key: jbyteArray,
    message_count: jint,
) -> jbyteArray {
    let bad_res = env.new_byte_array(0).unwrap();
    let dpk;
    match env.convert_byte_array(short_public_key) {
        Err(_) => return bad_res,
        Ok(s) => {
            if s.len() != DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE {
                return bad_res;
            }
            dpk = DeterministicPublicKey::from(*array_ref![
                s,
                0,
                DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE
            ]);
        }
    }
    let pk;
    match dpk.to_public_key(message_count as usize) {
        Err(_) => return bad_res,
        Ok(p) => pk = p,
    }
    if pk.validate().is_err() {
        return bad_res;
    }

    let pk_bytes = pk.to_bytes_compressed_form();
    match env.new_byte_array(pk_bytes.len() as jint) {
        Err(_) => bad_res,
        Ok(out) => {
            let pp: Vec<jbyte> = pk_bytes.iter().map(|b| *b as jbyte).collect();
            copy_to_jni!(env, out, pp.as_slice(), bad_res);
            out
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1init(_: JNIEnv, _: JObject) -> jlong {
    let mut error = ExternError::success();
    bbs_sign_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1set_1secret_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    secret_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(secret_key) {
        Err(_) => 1,
        Ok(s) => {
            if s.len() != FR_COMPRESSED_SIZE {
                2
            } else {
                let mut error = ExternError::success();
                let byte_array = ByteArray::from(s);
                bbs_sign_context_set_secret_key(handle as u64, byte_array, &mut error)
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut err = ExternError::success();
            SIGN_CONTEXT.call_with_result_mut(&mut err, handle as u64, |ctx| -> Result<(), BbsFfiError> {
                use std::convert::TryFrom;
                let v = PublicKey::try_from(s)?;
                ctx.public_key = Some(v);
                Ok(())
            });
            err.get_code().code()
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1add_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_sign_context_add_message_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1add_1message_1prehashed(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_sign_context_add_message_prehashed(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1sign_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut sig = ByteBuffer::from_vec(vec![]);
    let result = bbs_sign_context_finish(handle as u64, &mut sig, &mut error);
    if result != 0 {
        return result;
    }
    let sig: Vec<i8> = sig.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, signature, sig.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1init(_: JNIEnv, _: JObject) -> jlong {
    let mut error = ExternError::success();
    bbs_verify_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1add_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_context_add_message_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1add_1message_1prehashed(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_context_add_message_prehashed(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_context_set_public_key(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    match env.convert_byte_array(signature) {
        Err(_) => 1,
        Ok(s) => {
            if s.len() < G1_COMPRESSED_SIZE {
                2
            } else {
                let mut error = ExternError::success();
                let byte_array = ByteArray::from(s);
                bbs_verify_context_set_signature(handle as u64, byte_array, &mut error)
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    bbs_verify_context_finish(handle as u64, &mut error)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_blind_commitment_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1add_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    index: jint,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_commitment_context_add_message_bytes(
                handle as u64,
                index as u32,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1add_1prehashed(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    index: jint,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_commitment_context_add_message_prehashed(
                handle as u64,
                index as u32,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_commitment_context_set_public_key(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1set_1nonce_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    nonce: jbyteArray,
) -> jint {
    match env.convert_byte_array(nonce) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_commitment_context_set_nonce_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

/// commitment: [0u8; 48]
/// blinding_factor: [0u8; 32]
/// return proof: []byte
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1commitment_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    commitment: jbyteArray,
    blinding_factor: jbyteArray,
) -> jbyteArray {
    let mut error = ExternError::success();
    let mut c = ByteBuffer::from_vec(vec![]);
    let mut p = ByteBuffer::from_vec(vec![]);
    let mut r = ByteBuffer::from_vec(vec![]);
    let res =
        bbs_blind_commitment_context_finish(handle as u64, &mut c, &mut p, &mut r, &mut error);
    let bad_res = env.new_byte_array(0).unwrap();
    if res != 0 {
        return bad_res;
    }
    let cc: Vec<jbyte> = c.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, commitment, cc.as_slice(), bad_res);
    let rr: Vec<jbyte> = r.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, blinding_factor, rr.as_slice(), bad_res);
    let pp: Vec<jbyte> = p.destroy_into_vec().iter().map(|b| *b as jbyte).collect();

    match env.new_byte_array(pp.len() as jint) {
        Err(_) => env.new_byte_array(0).unwrap(),
        Ok(out) => {
            copy_to_jni!(env, out, pp.as_slice(), bad_res);
            out
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1init(_: JNIEnv, _: JObject) -> jlong {
    let mut error = ExternError::success();
    bbs_blind_sign_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1set_1secret_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    secret_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(secret_key) {
        Err(_) => 1,
        Ok(s) => {
            if s.len() != FR_COMPRESSED_SIZE {
                2
            } else {
                let mut error = ExternError::success();
                let byte_array = ByteArray::from(s);
                bbs_blind_sign_context_set_secret_key(handle as u64, byte_array, &mut error)
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_sign_context_set_public_key(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1set_1commitment(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    commitment: jbyteArray,
) -> jint {
    match env.convert_byte_array(commitment) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_sign_context_set_commitment(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1add_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    index: jint,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_sign_context_add_message_bytes(
                handle as u64,
                index as u32,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1add_1prehashed(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    index: jint,
    hash: jbyteArray,
) -> jint {
    match env.convert_byte_array(hash) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_blind_sign_context_add_message_prehashed(
                handle as u64,
                index as u32,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1blind_1sign_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    let mut err = ExternError::success();
    let mut s = ByteBuffer::from_vec(vec![]);
    let res = bbs_blind_sign_context_finish(handle as u64, &mut s, &mut err);
    if res != 0 {
        return res;
    }
    let ss: Vec<jbyte> = s.destroy_into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, signature, ss.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1unblind_1signature(
    env: JNIEnv,
    _: JObject,
    blind_signature: jbyteArray,
    blinding_factor: jbyteArray,
    unblind_signature: jbyteArray,
) -> jint {
    let mut err = ExternError::success();
    let bs;
    match env.convert_byte_array(blind_signature) {
        Err(_) => return 1,
        Ok(s) => bs = s,
    };
    let bf;
    match env.convert_byte_array(blinding_factor) {
        Err(_) => return 1,
        Ok(s) => bf = s,
    };

    let mut signature = ByteBuffer::default();
    let res = bbs_unblind_signature(
        ByteArray::from(bs),
        ByteArray::from(bf),
        &mut signature,
        &mut err,
    );
    if res != 0 {
        return res;
    }
    let signature: Vec<jbyte> = signature
        .destroy_into_vec()
        .iter()
        .map(|b| *b as jbyte)
        .collect();
    copy_to_jni!(env, unblind_signature, signature.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_create_proof_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            // let byte_array = ByteArray::from(s.clone());
            // bbs_create_proof_context_set_public_key(handle as u64, byte_array, &mut error)
            CREATE_PROOF_CONTEXT.call_with_result_mut(&mut error, handle as u64, |ctx| -> Result<(), BbsFfiError> {
                use std::convert::TryFrom;
                let v = PublicKey::try_from(s)?;
                ctx.public_key = Some(v);
                Ok(())
            });
            error.get_code().code()
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1set_1signature(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    signature: jbyteArray,
) -> jint {
    match env.convert_byte_array(signature) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            let res = bbs_create_proof_context_set_signature(handle as u64, byte_array, &mut error);
            if res != 0 {
                update_last_error(error.get_message().as_str());
            }
            res
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1set_1nonce_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    nonce: jbyteArray,
) -> jint {
    match env.convert_byte_array(nonce) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_create_proof_context_set_nonce_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1add_1proof_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
    xtype: jint,
    blinding_factor: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            let mut bf_byte_array = ByteArray::default();
            let proof_msg_type = match xtype {
                1 => ProofMessageType::Revealed,
                2 => ProofMessageType::HiddenProofSpecificBlinding,
                3 => {
                    match env.convert_byte_array(blinding_factor) {
                        Err(_) => return 0,
                        Ok(bf) => {
                            bf_byte_array = ByteArray::from(bf);
                        }
                    };
                    ProofMessageType::HiddenExternalBlinding
                }
                _ => return 2,
            };
            bbs_create_proof_context_add_proof_message_bytes(
                handle as u64,
                byte_array,
                proof_msg_type,
                bf_byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1size(_: JNIEnv, _: JObject, handle: jlong) -> jint {
    return bbs_create_proof_context_size(handle as u64)
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1create_1proof_1context_1finish(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    let mut error = ExternError::success();
    let mut p = ByteBuffer::from_vec(vec![]);
    let res = bbs_create_proof_context_finish(handle as u64, &mut p, &mut error);
    if res != 0 {
        return res;
    }
    let res = p.destroy_into_vec();
    let pp: Vec<jbyte> = res.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, proof, pp.as_slice());
    0
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1init(
    _: JNIEnv,
    _: JObject,
) -> jlong {
    let mut error = ExternError::success();
    bbs_verify_proof_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1add_1message_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_proof_context_add_message_bytes(
                handle as u64,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1add_1message_1prehashed(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    message: jbyteArray,
) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_proof_context_add_message_prehashed(
                handle as u64,
                byte_array,
                &mut error,
            )
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1set_1proof(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    proof: jbyteArray,
) -> jint {
    match env.convert_byte_array(proof) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from_slice(s.as_slice());
            let res = bbs_verify_proof_context_set_proof(handle as u64, byte_array, &mut error);
            if res != 0 {
                update_last_error(error.get_message().as_str());
            }
            res
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1set_1public_1key(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    public_key: jbyteArray,
) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            // let byte_array = ByteArray::from(s);
            // bbs_verify_proof_context_set_public_key(handle as u64, byte_array, &mut error)
            VERIFY_PROOF_CONTEXT.call_with_result_mut(&mut error, handle as u64, |ctx| -> Result<(), BbsFfiError> {
                use std::convert::TryFrom;
                let v = PublicKey::try_from(s)?;
                ctx.public_key = Some(v);
                Ok(())
            });
            error.get_code().code()
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1set_1nonce_1bytes(
    env: JNIEnv,
    _: JObject,
    handle: jlong,
    nonce: jbyteArray,
) -> jint {
    match env.convert_byte_array(nonce) {
        Err(_) => 1,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_verify_proof_context_set_nonce_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1verify_1proof_1context_1finish(
    _: JNIEnv,
    _: JObject,
    handle: jlong,
) -> jint {
    let mut error = ExternError::success();
    bbs_verify_proof_context_finish(handle as u64, &mut error)
}

fn get_secret_key(env: &JNIEnv, secret_key: jbyteArray) -> Result<SecretKey, jint> {
    match env.convert_byte_array(secret_key) {
        Err(_) => Err(0),
        Ok(s) => {
            if s.len() != FR_COMPRESSED_SIZE {
                return Err(0);
            } else {
                Ok(SecretKey::from(array_ref![s, 0, FR_COMPRESSED_SIZE]))
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_bbs_signatures_Bbs_bbs_1get_1total_1messages_1count_1for_1proof(env: JNIEnv, _: JObject, proof: jbyteArray) -> jint {
    match env.convert_byte_array(proof) {
        Err(_) => -1,
        Ok(s) => {
            if s.len() < 2 {
                -1
            } else {
                u16::from_be_bytes(*array_ref![s, 0, 2]) as jint
            }
        }
    }
}