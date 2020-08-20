
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
use jni::sys::{jbyteArray, jobject, jint};


// TODO discuss what we will call the android package name e.g reactnativernbbssignatures
#[allow(non_snake_case)]
#[no_mangle]
pub extern fn Java_com_reactnativernbbssignatures_Native_bls_1generate_1key(
  env: JNIEnv, _: JObject, seed: jbyteArray, public_key: jbyteArray, secret_key: jbyteArray
) -> i32 {
      let seed_data = env.convert_byte_array(seed).unwrap();
      let mut vec: Vec<i8> = vec![0, 1, 2, 3];
      let buf = vec.as_slice();
      env.set_byte_array_region(public_key, 0, buf).unwrap();
      env.set_byte_array_region(secret_key, 0, buf).unwrap();
      100
      generate_keys(
        seed_data.to_opt_vec().map(|v| KeyGenOption::UseSeed(v)),
        public_key,
        secret_key,
        err,
      )
      )
}
