
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
use jni::sys::{jbyteArray, jobject, jint, jbyte};

use crate::*;


#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn Java_Bbs_bls_1generate_1g1_1key(env: JNIEnv, _: JObject, seed: jbyteArray, blinding_factor: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray) -> i32 {
    let ikm;
    match env.convert_byte_array(seed) {
        Err(_) => return 0,
        Ok(s) => ikm = s,
    };
    let s = if ikm.is_empty() { None } else { Some(ikm) };
    let (r, pk_bytes, sk_bytes) = bls_generate_g1_key(s);
    let pk = pk_bytes.iter().map(|b| b as jbyte).collect();
    let sk = sk_bytes.iter().map(|b| b as jbyte).collect();
    if let Some(bf) = r {
        let b = bf.iter().map(|b| b as jbyte).collect();
        env.set_byte_array_region(blinding_factor, 0, b).unwrap();
    }
    env.set_byte_array_region(public_key, 0, pk).unwrap();
    env.set_byte_array_region(secret_key, 0, sk).unwrap();
    1
}


// TODO discuss what we will call the android package name e.g reactnativernbbssignatures
// #[allow(non_snake_case)]
// #[no_mangle]
// pub extern fn Java_com_reactnativernbbssignatures_Native_bls_1generate_1key(
//   env: JNIEnv, _: JObject, seed: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray
// ) -> i32 {
//       let seed_data = env.convert_byte_array(seed).unwrap();
//       let mut vec: Vec<i8> = vec![0, 1, 2, 3];
//       let buf = vec.as_slice();
//       env.set_byte_array_region(public_key, 0, buf).unwrap();
//       env.set_byte_array_region(secret_key, 0, buf).unwrap();
//       100
//       generate_keys(
//         seed_data.to_opt_vec().map(|v| KeyGenOption::UseSeed(v)),
//         public_key,
//         secret_key,
//         err,
//       )
//       )
// }
