
// This is the interface to the JVM that we'll
// call the majority of our methods on.
use jni::JNIEnv;

// These objects are what you should use as arguments to your native function.
// They carry extra lifetime information to prevent them escaping this context
// and getting used after being GC'd.
use jni::objects::{JObject, JValue};

// This is just a pointer. We'll be returning it from our function.
// We can't return one of the objects with lifetime information because the
// lifetime checker won't let us.
use jni::sys::{jbyteArray, jint, jlong, jbyte};

use crate::*;
use bbs::keys::{DeterministicPublicKey, KeyGenOption, SecretKey, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE};
use bbs::{ToVariableLengthBytes, FR_COMPRESSED_SIZE, G2_COMPRESSED_SIZE};
use crate::bbs_sign::*;


#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1generate_1g1_1key(env: JNIEnv, _: JObject, seed: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 0,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (pk_bytes, sk_bytes) = bls_generate_g1_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1generate_1g2_1key(env: JNIEnv, _: JObject, seed: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 0,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (pk_bytes, sk_bytes) = bls_generate_g2_key(s);
    let pk: Vec<i8> = pk_bytes.iter().map(|b| *b as jbyte).collect();
    let sk: Vec<i8> = sk_bytes.iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, public_key, pk.as_slice());
    copy_to_jni!(env, secret_key, sk.as_slice());
    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1generate_1blinded_1g1_1key(env: JNIEnv, _: JObject, seed: jbyteArray, bf: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 0,
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
    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1generate_1blinded_1g2_1key(env: JNIEnv, _: JObject, seed: jbyteArray, bf: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray) -> jint {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 0,
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
    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1secret_1key_1to_1bbs_1key(env: JNIEnv, _: JObject, secret_key: jbyteArray, message_count: jint, public_key: JObject) -> jint {
    let sk = get_secret_key(&env, secret_key);
    if sk.is_err() {
        return 0;
    }
    let sk = sk.unwrap();
    let (dpk, _) = DeterministicPublicKey::new(Some(KeyGenOption::FromSecretKey(sk)));
    let pk;
    match dpk.to_public_key(message_count as usize) {
        Err(_) => return 0,
        Ok(p) => pk = p
    };
    if pk.validate().is_err() {
        return 0;
    }

    let pk_bytes: Vec<JValue> = pk.to_bytes_compressed_form().iter().map(|b| JValue::Byte(*b as jbyte)).collect();

    // TODO: test whether this actually works
    if env.call_method(public_key, "put", "[B", pk_bytes.as_slice()).is_err() {
        return 0;
    }

    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1public_1key_1to_1bbs_1key(env: JNIEnv, _: JObject, short_public_key: jbyteArray, message_count: jint, public_key: JObject) -> jint {
    let dpk;
    match env.convert_byte_array(short_public_key) {
        Err(_) => return 0,
        Ok(s) => {
            if s.len() != DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE {
                return 0;
            }
            dpk = DeterministicPublicKey::from(*array_ref![s, 0, DETERMINISTIC_PUBLIC_KEY_COMPRESSED_SIZE]);
        }
    }
    let pk;
    match dpk.to_public_key(message_count as usize) {
        Err(_) => return 0,
        Ok(p) => pk = p
    }
    if pk.validate().is_err() {
        return 0;
    }

    let pk_bytes: Vec<JValue> = pk.to_bytes_compressed_form().iter().map(|b| JValue::Byte(*b as jbyte)).collect();

    // TODO: test whether this actually works
    if env.call_method(public_key, "put", "[B", pk_bytes.as_slice()).is_err() {
        return 0;
    }

    1
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bbs_1sign_1init(_: JNIEnv, _: JObject) -> jlong {
    let mut error = ExternError::success();
    bbs_sign_context_init(&mut error) as jlong
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bbs_1sign_1set_1secret_1key(env: JNIEnv, _: JObject, handle: jlong, secret_key: jbyteArray) -> jint {
    match env.convert_byte_array(secret_key) {
        Err(_) => 0,
        Ok(s) => {
            if s.len() != FR_COMPRESSED_SIZE {
                0
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
pub extern "C" fn Java_Bbs_bbs_1sign_1set_1public_1key(env: JNIEnv, _: JObject, handle: jlong, public_key: jbyteArray) -> jint {
    match env.convert_byte_array(public_key) {
        Err(_) => 0,
        Ok(s) => {
            if s.len() != G2_COMPRESSED_SIZE {
                0
            } else {
                let mut error = ExternError::success();
                let byte_array = ByteArray::from(s);
                bbs_sign_context_set_public_key(handle as u64, byte_array, &mut error)
            }
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bbs_1sign_1add_1message_1bytes(env: JNIEnv, _: JObject, handle: jlong, message: jbyteArray) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 0,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_sign_context_add_message_bytes(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bbs_1sign_1add_1message_1prehashed(env: JNIEnv, _: JObject, handle: jlong, message: jbyteArray) -> jint {
    match env.convert_byte_array(message) {
        Err(_) => 0,
        Ok(s) => {
            let mut error = ExternError::success();
            let byte_array = ByteArray::from(s);
            bbs_sign_context_add_message_prehashed(handle as u64, byte_array, &mut error)
        }
    }
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bbs_1sign_1finish(env: JNIEnv, _: JObject, handle: jlong, signature: jbyteArray) -> jint {
    let mut error = ExternError::success();
    let mut sig = ByteBuffer::from_vec(vec![]);
    let result = bbs_sign_context_finish(handle as u64, &mut sig, &mut error);
    if result == 0 {
        return result;
    }
    let sig: Vec<i8> = sig.into_vec().iter().map(|b| *b as jbyte).collect();
    copy_to_jni!(env, signature, sig.as_slice());
    1
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