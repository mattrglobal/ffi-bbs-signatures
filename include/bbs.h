#ifndef __bbs__plus__included__
#define __bbs__plus__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum ProofMessageType {
  Revealed = 1,
  HiddenProofSpecificBlinding = 2,
  HiddenExternalBlinding = 3,
} ProofMessageType;

/**
 * ByteBuffer is a struct that represents an array of bytes to be sent over the FFI boundaries.
 * There are several cases when you might want to use this, but the primary one for us
 * is for returning protobuf-encoded data to Swift and Java. The type is currently rather
 * limited (implementing almost no functionality), however in the future it may be
 * more expanded.
 *
 * ## Caveats
 *
 * Note that the order of the fields is `len` (an i64) then `data` (a `*mut u8`), getting
 * this wrong on the other side of the FFI will cause memory corruption and crashes.
 * `i64` is used for the length instead of `u64` and `usize` because JNA has interop
 * issues with both these types.
 *
 * ### `Drop` is not implemented
 *
 * ByteBuffer does not implement Drop. This is intentional. Memory passed into it will
 * be leaked if it is not explicitly destroyed by calling [`ByteBuffer::destroy`], or
 * [`ByteBuffer::destroy_into_vec`]. This is for two reasons:
 *
 * 1. In the future, we may allow it to be used for data that is not managed by
 *    the Rust allocator\*, and `ByteBuffer` assuming it's okay to automatically
 *    deallocate this data with the Rust allocator.
 *
 * 2. Automatically running destructors in unsafe code is a
 *    [frequent footgun](https://without.boats/blog/two-memory-bugs-from-ringbahn/)
 *    (among many similar issues across many crates).
 *
 * Note that calling `destroy` manually is often not needed, as usually you should
 * be passing these to the function defined by [`define_bytebuffer_destructor!`] from
 * the other side of the FFI.
 *
 * Because this type is essentially *only* useful in unsafe or FFI code (and because
 * the most common usage pattern does not require manually managing the memory), it
 * does not implement `Drop`.
 *
 * \* Note: in the case of multiple Rust shared libraries loaded at the same time,
 * there may be multiple instances of "the Rust allocator" (one per shared library),
 * in which case we're referring to whichever instance is active for the code using
 * the `ByteBuffer`. Note that this doesn't occur on all platforms or build
 * configurations, but treating allocators in different shared libraries as fully
 * independent is always safe.
 *
 * ## Layout/fields
 *
 * This struct's field are not `pub` (mostly so that we can soundly implement `Send`, but also so
 * that we can verify rust users are constructing them appropriately), the fields, their types, and
 * their order are *very much* a part of the public API of this type. Consumers on the other side
 * of the FFI will need to know its layout.
 *
 * If this were a C struct, it would look like
 *
 * ```c,no_run
 * struct ByteBuffer {
 *     // Note: This should never be negative, but values above
 *     // INT64_MAX / i64::MAX are not allowed.
 *     int64_t len;
 *     // Note: nullable!
 *     uint8_t *data;
 * };
 * ```
 *
 * In rust, there are two fields, in this order: `len: i64`, and `data: *mut u8`.
 *
 * For clarity, the fact that the data pointer is nullable means that `Option<ByteBuffer>` is not
 * the same size as ByteBuffer, and additionally is not FFI-safe (the latter point is not
 * currently guaranteed anyway as of the time of writing this comment).
 *
 * ### Description of fields
 *
 * `data` is a pointer to an array of `len` bytes. Note that data can be a null pointer and therefore
 * should be checked.
 *
 * The bytes array is allocated on the heap and must be freed on it as well. Critically, if there
 * are multiple rust shared libraries using being used in the same application, it *must be freed
 * on the same heap that allocated it*, or you will corrupt both heaps.
 *
 * Typically, this object is managed on the other side of the FFI (on the "FFI consumer"), which
 * means you must expose a function to release the resources of `data` which can be done easily
 * using the [`define_bytebuffer_destructor!`] macro provided by this crate.
 */
typedef struct ByteBuffer {
  int64_t len;
  uint8_t *data;
} ByteBuffer;

/**
 * A wrapper around error codes, which is represented identically to an i32 on the other side of
 * the FFI. Essentially exists to check that we don't accidentally reuse success/panic codes for
 * other things.
 */
typedef int32_t ErrorCode;

/**
 * Represents an error that occured within rust, storing both an error code, and additional data
 * that may be used by the caller.
 *
 * Misuse of this type can cause numerous issues, so please read the entire documentation before
 * usage.
 *
 * ## Rationale
 *
 * This library encourages a pattern of taking a `&mut ExternError` as the final parameter for
 * functions exposed over the FFI. This is an "out parameter" which we use to write error/success
 * information that occurred during the function's execution.
 *
 * To be clear, this means instances of `ExternError` will be created on the other side of the FFI,
 * and passed (by mutable reference) into Rust.
 *
 * While this pattern is not particularly ergonomic in Rust (although hopefully this library
 * helps!), it offers two main benefits over something more ergonomic (which might be `Result`
 * shaped).
 *
 * 1. It avoids defining a large number of `Result`-shaped types in the FFI consumer, as would
 *    be required with something like an `struct ExternResult<T> { ok: *mut T, err:... }`
 *
 * 2. It offers additional type safety over `struct ExternResult { ok: *mut c_void, err:... }`,
 *    which helps avoid memory safety errors. It also can offer better performance for returning
 *    primitives and repr(C) structs (no boxing required).
 *
 * It also is less tricky to use properly than giving consumers a `get_last_error()` function, or
 * similar.
 *
 * ## Caveats
 *
 * Note that the order of the fields is `code` (an i32) then `message` (a `*mut c_char`), getting
 * this wrong on the other side of the FFI will cause memory corruption and crashes.
 *
 * The fields are public largely for documentation purposes, but you should use
 * [`ExternError::new_error`] or [`ExternError::success`] to create these.
 *
 * ## Layout/fields
 *
 * This struct's field are not `pub` (mostly so that we can soundly implement `Send`, but also so
 * that we can verify rust users are constructing them appropriately), the fields, their types, and
 * their order are *very much* a part of the public API of this type. Consumers on the other side
 * of the FFI will need to know its layout.
 *
 * If this were a C struct, it would look like
 *
 * ```c,no_run
 * struct ExternError {
 *     int32_t code;
 *     char *message; // note: nullable
 * };
 * ```
 *
 * In rust, there are two fields, in this order: `code: ErrorCode`, and `message: *mut c_char`.
 * Note that ErrorCode is a `#[repr(transparent)]` wrapper around an `i32`, so the first property
 * is equivalent to an `i32`.
 *
 * #### The `code` field.
 *
 * This is the error code, 0 represents success, all other values represent failure. If the `code`
 * field is nonzero, there should always be a message, and if it's zero, the message will always be
 * null.
 *
 * #### The `message` field.
 *
 * This is a null-terminated C string containing some amount of additional information about the
 * error. If the `code` property is nonzero, there should always be an error message. Otherwise,
 * this should will be null.
 *
 * This string (when not null) is allocated on the rust heap (using this crate's
 * [`rust_string_to_c`]), and must be freed on it as well. Critically, if there are multiple rust
 * packages using being used in the same application, it *must be freed on the same heap that
 * allocated it*, or you will corrupt both heaps.
 *
 * Typically, this object is managed on the other side of the FFI (on the "FFI consumer"), which
 * means you must expose a function to release the resources of `message` which can be done easily
 * using the [`define_string_destructor!`] macro provided by this crate.
 *
 * If, for some reason, you need to release the resources directly, you may call
 * `ExternError::release()`. Note that you probably do not need to do this, and it's
 * intentional that this is not called automatically by implementing `drop`.
 *
 * ## Example
 *
 * ```rust,no_run
 * use ffi_support::{ExternError, ErrorCode};
 *
 * #[derive(Debug)]
 * pub enum MyError {
 *     IllegalFoo(String),
 *     InvalidBar(i64),
 *     // ...
 * }
 *
 * // Putting these in a module is obviously optional, but it allows documentation, and helps
 * // avoid accidental reuse.
 * pub mod error_codes {
 *     // note: -1 and 0 are reserved by ffi_support
 *     pub const ILLEGAL_FOO: i32 = 1;
 *     pub const INVALID_BAR: i32 = 2;
 *     // ...
 * }
 *
 * fn get_code(e: &MyError) -> ErrorCode {
 *     match e {
 *         MyError::IllegalFoo(_) => ErrorCode::new(error_codes::ILLEGAL_FOO),
 *         MyError::InvalidBar(_) => ErrorCode::new(error_codes::INVALID_BAR),
 *         // ...
 *     }
 * }
 *
 * impl From<MyError> for ExternError {
 *     fn from(e: MyError) -> ExternError {
 *         ExternError::new_error(get_code(&e), format!("{:?}", e))
 *     }
 * }
 * ```
 */
typedef struct ExternError {
  ErrorCode code;
  char *message;
} ExternError;

/**
 * `FfiStr<'a>` is a safe (`#[repr(transparent)]`) wrapper around a
 * nul-terminated `*const c_char` (e.g. a C string). Conceptually, it is
 * similar to [`std::ffi::CStr`], except that it may be used in the signatures
 * of extern "C" functions.
 *
 * Functions accepting strings should use this instead of accepting a C string
 * directly. This allows us to write those functions using safe code without
 * allowing safe Rust to cause memory unsafety.
 *
 * A single function for constructing these from Rust ([`FfiStr::from_raw`])
 * has been provided. Most of the time, this should not be necessary, and users
 * should accept `FfiStr` in the parameter list directly.
 *
 * ## Caveats
 *
 * An effort has been made to make this struct hard to misuse, however it is
 * still possible, if the `'static` lifetime is manually specified in the
 * struct. E.g.
 *
 * ```rust,no_run
 * # use ffi_support::FfiStr;
 * // NEVER DO THIS
 * #[no_mangle]
 * extern "C" fn never_do_this(s: FfiStr<'static>) {
 *     // save `s` somewhere, and access it after this
 *     // function returns.
 * }
 * ```
 *
 * Instead, one of the following patterns should be used:
 *
 * ```
 * # use ffi_support::FfiStr;
 * #[no_mangle]
 * extern "C" fn valid_use_1(s: FfiStr<'_>) {
 *     // Use of `s` after this function returns is impossible
 * }
 * // Alternative:
 * #[no_mangle]
 * extern "C" fn valid_use_2(s: FfiStr) {
 *     // Use of `s` after this function returns is impossible
 * }
 * ```
 */
typedef const char *FfiStr;

/**
 * Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
 * If Rust allocated, then the outgoing struct is `ffi_support::ByteBuffer`
 * Caller is responsible for calling free where applicable.
 *
 * C will not notice a difference and can use the same struct
 */
typedef struct ByteArray {
  uintptr_t length;
  const uint8_t *data;
} ByteArray;

/**
 * Public destructor for strings managed by the other side of the FFI.
 *
 * # Safety
 *
 * This will free the string pointer it gets passed in as an argument,
 * and thus can be wildly unsafe if misused.
 *
 * See the documentation of `ffi_support::destroy_c_string` and
 * `ffi_support::define_string_destructor!` for further info.
 */
void bbs_string_free(char *s);

void bbs_byte_buffer_free(struct ByteBuffer v);

void free_bbs_blind_commitment(uint64_t v, struct ExternError *err);

int32_t bbs_blind_signature_size(void);

uint64_t bbs_blind_commitment_context_init(struct ExternError *err);

int32_t bbs_blind_commitment_context_add_message_string(uint64_t handle,
                                                        uint32_t index,
                                                        FfiStr message,
                                                        struct ExternError *err);

int32_t bbs_blind_commitment_context_add_message_bytes(uint64_t handle,
                                                       uint32_t index,
                                                       struct ByteArray message,
                                                       struct ExternError *err);

int32_t bbs_blind_commitment_context_add_message_prehashed(uint64_t handle,
                                                           uint32_t index,
                                                           struct ByteArray message,
                                                           struct ExternError *err);

int32_t bbs_blind_commitment_context_set_public_key(uint64_t handle,
                                                    struct ByteArray value,
                                                    struct ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                      FfiStr message,
                                                      struct ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                     struct ByteArray value,
                                                     struct ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                         struct ByteArray value,
                                                         struct ExternError *err);

int32_t bbs_blind_commitment_context_finish(uint64_t handle,
                                            struct ByteBuffer *commitment,
                                            struct ByteBuffer *out_context,
                                            struct ByteBuffer *blinding_factor,
                                            struct ExternError *err);

void free_bbs_blind_sign(uint64_t v, struct ExternError *err);

int32_t bbs_blinding_factor_size(void);

uint64_t bbs_blind_sign_context_init(struct ExternError *err);

int32_t bbs_blind_sign_context_add_message_string(uint64_t handle,
                                                  uint32_t index,
                                                  FfiStr message,
                                                  struct ExternError *err);

int32_t bbs_blind_sign_context_add_message_bytes(uint64_t handle,
                                                 uint32_t index,
                                                 struct ByteArray message,
                                                 struct ExternError *err);

int32_t bbs_blind_sign_context_add_message_prehashed(uint64_t handle,
                                                     uint32_t index,
                                                     struct ByteArray message,
                                                     struct ExternError *err);

int32_t bbs_blind_sign_context_set_public_key(uint64_t handle,
                                              struct ByteArray value,
                                              struct ExternError *err);

int32_t bbs_blind_sign_context_set_secret_key(uint64_t handle,
                                              struct ByteArray value,
                                              struct ExternError *err);

int32_t bbs_blind_sign_context_set_commitment(uint64_t handle,
                                              struct ByteArray value,
                                              struct ExternError *err);

int32_t bbs_blind_sign_context_finish(uint64_t handle,
                                      struct ByteBuffer *blinded_signature,
                                      struct ExternError *err);

int32_t bbs_unblind_signature(struct ByteArray blind_signature,
                              struct ByteArray blinding_factor,
                              struct ByteBuffer *unblind_signature,
                              struct ExternError *err);

void free_create_proof(uint64_t v, struct ExternError *err);

int32_t bbs_create_proof_context_size(uint64_t handle);

uint64_t bbs_create_proof_context_init(struct ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_string(uint64_t handle,
                                                          FfiStr message,
                                                          enum ProofMessageType xtype,
                                                          struct ByteArray blinding_factor,
                                                          struct ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_bytes(uint64_t handle,
                                                         struct ByteArray message,
                                                         enum ProofMessageType xtype,
                                                         struct ByteArray blinding_factor,
                                                         struct ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_prehashed(uint64_t handle,
                                                             struct ByteArray message,
                                                             enum ProofMessageType xtype,
                                                             struct ByteArray blinding_factor,
                                                             struct ExternError *err);

int32_t bbs_create_proof_context_set_signature(uint64_t handle,
                                               struct ByteArray value,
                                               struct ExternError *err);

int32_t bbs_create_proof_context_set_public_key(uint64_t handle,
                                                struct ByteArray value,
                                                struct ExternError *err);

int32_t bbs_create_proof_context_set_nonce_string(uint64_t handle,
                                                  FfiStr message,
                                                  struct ExternError *err);

int32_t bbs_create_proof_context_set_nonce_bytes(uint64_t handle,
                                                 struct ByteArray value,
                                                 struct ExternError *err);

int32_t bbs_create_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     struct ByteArray value,
                                                     struct ExternError *err);

int32_t bbs_create_proof_context_finish(uint64_t handle,
                                        struct ByteBuffer *proof,
                                        struct ExternError *err);

void free_bbs_sign(uint64_t v, struct ExternError *err);

int32_t bbs_signature_size(void);

uint64_t bbs_sign_context_init(struct ExternError *err);

int32_t bbs_sign_context_add_message_string(uint64_t handle,
                                            FfiStr message,
                                            struct ExternError *err);

int32_t bbs_sign_context_add_message_bytes(uint64_t handle,
                                           struct ByteArray message,
                                           struct ExternError *err);

int32_t bbs_sign_context_add_message_prehashed(uint64_t handle,
                                               struct ByteArray message,
                                               struct ExternError *err);

int32_t bbs_sign_context_set_secret_key(uint64_t handle,
                                        struct ByteArray value,
                                        struct ExternError *err);

int32_t bbs_sign_context_set_public_key(uint64_t handle,
                                        struct ByteArray value,
                                        struct ExternError *err);

int32_t bbs_sign_context_finish(uint64_t handle,
                                struct ByteBuffer *signature,
                                struct ExternError *err);

uint64_t bbs_verify_context_init(struct ExternError *err);

int32_t bbs_verify_context_add_message_string(uint64_t handle,
                                              FfiStr message,
                                              struct ExternError *err);

int32_t bbs_verify_context_add_message_bytes(uint64_t handle,
                                             struct ByteArray message,
                                             struct ExternError *err);

int32_t bbs_verify_context_add_message_prehashed(uint64_t handle,
                                                 struct ByteArray message,
                                                 struct ExternError *err);

int32_t bbs_verify_context_set_public_key(uint64_t handle,
                                          struct ByteArray public_key,
                                          struct ExternError *err);

int32_t bbs_verify_context_set_signature(uint64_t handle,
                                         struct ByteArray value,
                                         struct ExternError *err);

int32_t bbs_verify_context_finish(uint64_t handle, struct ExternError *err);

void free_verify_proof(uint64_t v, struct ExternError *err);

int32_t bbs_get_total_messages_count_for_proof(struct ByteArray proof);

uint64_t bbs_verify_proof_context_init(struct ExternError *err);

int32_t bbs_verify_proof_context_add_message_string(uint64_t handle,
                                                    FfiStr message,
                                                    struct ExternError *err);

int32_t bbs_verify_proof_context_add_message_bytes(uint64_t handle,
                                                   struct ByteArray message,
                                                   struct ExternError *err);

int32_t bbs_verify_proof_context_add_message_prehashed(uint64_t handle,
                                                       struct ByteArray message,
                                                       struct ExternError *err);

int32_t bbs_verify_proof_context_set_proof(uint64_t handle,
                                           struct ByteArray value,
                                           struct ExternError *err);

int32_t bbs_verify_proof_context_set_public_key(uint64_t handle,
                                                struct ByteArray value,
                                                struct ExternError *err);

int32_t bbs_verify_proof_context_set_nonce_string(uint64_t handle,
                                                  FfiStr message,
                                                  struct ExternError *err);

int32_t bbs_verify_proof_context_set_nonce_bytes(uint64_t handle,
                                                 struct ByteArray value,
                                                 struct ExternError *err);

int32_t bbs_verify_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     struct ByteArray value,
                                                     struct ExternError *err);

int32_t bbs_verify_proof_context_finish(uint64_t handle, struct ExternError *err);

void free_verify_sign_proof(uint64_t v, struct ExternError *err);

uint64_t bbs_verify_blind_commitment_context_init(struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_add_blinded(uint64_t handle,
                                                        uint32_t index,
                                                        struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_public_key(uint64_t handle,
                                                           struct ByteArray value,
                                                           struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                             FfiStr message,
                                                             struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                            struct ByteArray value,
                                                            struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                                struct ByteArray value,
                                                                struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_proof(uint64_t handle,
                                                      struct ByteArray value,
                                                      struct ExternError *err);

int32_t bbs_verify_blind_commitment_context_finish(uint64_t handle, struct ExternError *err);

int32_t bls_secret_key_size(void);

int32_t bls_public_key_g2_size(void);

int32_t blinding_factor_size(void);

int32_t bls_public_key_g1_size(void);

int32_t bls_generate_g2_key(struct ByteArray seed,
                            struct ByteBuffer *public_key,
                            struct ByteBuffer *secret_key,
                            struct ExternError *err);

int32_t bls_generate_g1_key(struct ByteArray seed,
                            struct ByteBuffer *public_key,
                            struct ByteBuffer *secret_key,
                            struct ExternError *err);

int32_t bls_generate_blinded_g2_key(struct ByteArray seed,
                                    struct ByteBuffer *public_key,
                                    struct ByteBuffer *secret_key,
                                    struct ByteBuffer *blinding_factor,
                                    struct ExternError *err);

int32_t bls_generate_blinded_g1_key(struct ByteArray seed,
                                    struct ByteBuffer *public_key,
                                    struct ByteBuffer *secret_key,
                                    struct ByteBuffer *blinding_factor,
                                    struct ExternError *err);

int32_t bls_get_public_key(struct ByteArray secret_key,
                           struct ByteBuffer *public_key,
                           struct ExternError *err);

int32_t bls_secret_key_to_bbs_key(struct ByteArray secret_key,
                                  uint32_t message_count,
                                  struct ByteBuffer *public_key,
                                  struct ExternError *err);

int32_t bls_public_key_to_bbs_key(struct ByteArray d_public_key,
                                  uint32_t message_count,
                                  struct ByteBuffer *public_key,
                                  struct ExternError *err);

#endif /* __bbs__plus__included__ */
