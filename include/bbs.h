#ifndef __bbs__plus__included__
#define __bbs__plus__included__

#include <stdint.h>

/* Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
*  If Rust allocated, then the outgoing struct is `ffi_support::ByteBuffer`
*  Caller is responsible for calling free where applicable.
*/
typedef struct {
    int64_t len;
    uint8_t *_Nullable data;
} ByteBuffer;

typedef struct {
    int32_t code;
    char* message; /* note: nullable */
} ExternError;

typedef enum {
    Revealed = 1,
    HiddenProofSpecificBlinding = 2,
    HiddenExternalBlinding = 3,
} proof_message_t;

typedef enum {
    /* The proof verified */
    Success = 200,
    /* The proof failed because the signature proof of knowledge failed */
    BadSignature = 400,
    /* The proof failed because a hidden message was invalid when the proof was created */
    BadHiddenMessage = 401,
    /* The proof failed because a revealed message was invalid */
    BadRevealedMessage = 402,
} signature_proof_status;

#ifdef __cplusplus
extern "C" {
#endif

void bbs_string_free(char* string);
void bbs_byte_buffer_free(ByteBuffer data);

uint64_t bbs_blind_commitment_context_init(ExternError *err);

int32_t bbs_blind_commitment_context_finish(uint64_t handle,
                                            ByteBuffer *commitment,
                                            ByteBuffer *out_context,
                                            ByteBuffer *blinding_factor,
                                            ExternError *err);

int32_t bbs_blind_commitment_context_add_message_string(uint64_t handle,
                                                        uint32_t index,
                                                        const char *const message,
                                                        ExternError *err);

int32_t bbs_blind_commitment_context_add_message_bytes(uint64_t handle,
                                                       uint32_t index,
                                                       ByteBuffer message,
                                                       ExternError *err);

int32_t bbs_blind_commitment_context_add_message_prehashed(uint64_t handle,
                                                           uint32_t index,
                                                           ByteBuffer message,
                                                           ExternError *err);

int32_t bbs_blind_commitment_context_set_public_key(uint64_t handle,
                                                    ByteBuffer public_key,
                                                    ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                      const char *const message,
                                                      ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                     ByteBuffer message,
                                                     ExternError *err);

int32_t bbs_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                         ByteBuffer message,
                                                         ExternError *err);

int32_t bbs_blind_sign_context_finish(uint64_t handle,
                                      ByteBuffer *blinded_signature,
                                      ExternError *err);

int32_t bbs_blind_sign_context_add_message_string(uint64_t handle,
                                                  uint32_t index,
                                                  const char *const message,
                                                  ExternError *err);

int32_t bbs_blind_sign_context_add_message_bytes(uint64_t handle,
                                                 uint32_t index,
                                                 ByteBuffer message,
                                                 ExternError *err);

int32_t bbs_blind_sign_context_add_message_prehashed(uint64_t handle,
                                                     uint32_t index,
                                                     ByteBuffer message,
                                                     ExternError *err);

int32_t bbs_blind_sign_context_set_secret_key(uint64_t handle,
                                              ByteBuffer secret_key,
                                              ExternError *err);

int32_t bbs_blind_sign_context_set_public_key(uint64_t handle,
                                              ByteBuffer public_key,
                                              ExternError *err);

int32_t bbs_blind_sign_context_set_commitment(uint64_t handle,
                                              ByteBuffer public_key ,
                                              ExternError *err);

uint64_t bbs_blind_sign_context_init(ExternError *err);

int32_t bbs_blind_signature_size(void);

int32_t bbs_unblind_signature(ByteBuffer blind_signature,
                              ByteBuffer blinding_factor,
                              ByteBuffer *unblind_signature,
                              ExternError *err);

int32_t bbs_create_proof_context_finish(uint64_t handle, ByteBuffer *proof, ExternError *err);

int32_t bbs_create_proof_context_set_public_key(uint64_t handle,
                                                ByteBuffer public_key,
                                                ExternError *err);

int32_t bbs_create_proof_context_set_signature(uint64_t handle,
                                               ByteBuffer signature ,
                                               ExternError *err);

int32_t bbs_create_proof_context_set_nonce_string(uint64_t handle,
                                                  const char *const message ,
                                                  ExternError *err);

int32_t bbs_create_proof_context_set_nonce_bytes(uint64_t handle,
                                                 ByteBuffer message,
                                                 ExternError *err);

int32_t bbs_create_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     ByteBuffer message,
                                                     ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_string(uint64_t handle,
                                                          const char *const message,
                                                          proof_message_t xtype,
                                                          ByteBuffer blinding_factor,
                                                          ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_bytes(uint64_t handle,
                                                         ByteBuffer message,
                                                         proof_message_t xtype,
                                                         ByteBuffer blinding_factor,
                                                         ExternError *err);

int32_t bbs_create_proof_context_add_proof_message_prehashed(uint64_t handle,
                                                             ByteBuffer message,
                                                             proof_message_t xtype,
                                                             ByteBuffer blinding_factor,
                                                             ExternError *err);

uint64_t bbs_create_proof_context_init(ExternError *err);

int32_t bbs_sign_context_add_message_string(uint64_t handle,
                                            const char *const message,
                                            ExternError *err);

int32_t bbs_sign_context_add_message_bytes(uint64_t handle,
                                           ByteBuffer message,
                                           ExternError *err);

int32_t bbs_sign_context_add_message_prehashed(uint64_t handle,
                                               ByteBuffer message,
                                               ExternError *err);

int32_t bbs_sign_context_set_secret_key(uint64_t handle,
                                        ByteBuffer secret_key,
                                        ExternError *err);

int32_t bbs_sign_context_set_public_key(uint64_t handle,
                                        ByteBuffer public_key,
                                        ExternError *err);

int32_t bbs_sign_context_finish(uint64_t handle, ByteBuffer *signature, ExternError *err);

uint64_t bbs_sign_context_init(ExternError *err);

int32_t bbs_signature_size(void);

int32_t bbs_verify_context_add_message_bytes(uint64_t handle,
                                             ByteBuffer message,
                                             ExternError *err);

int32_t bbs_verify_context_add_message_prehashed(uint64_t handle,
                                                 ByteBuffer message,
                                                 ExternError *err);

int32_t bbs_verify_context_add_message_string(uint64_t handle,
                                              const char *const message,
                                              ExternError *err);

int32_t bbs_verify_context_set_public_key(uint64_t handle,
                                          ByteBuffer public_key,
                                          ExternError *err);
int32_t bbs_verify_context_set_signature(uint64_t handle,
                                         ByteBuffer signature,
                                         ExternError *err);

int32_t bbs_verify_context_finish(uint64_t handle, ExternError *err);

uint64_t bbs_verify_context_init(ExternError *err);

int32_t bbs_verify_blind_commitment_context_add_blinded(uint64_t handle,
                                                        uint32_t index,
                                                        ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_public_key(uint64_t handle,
                                                           ByteBuffer public_key,
                                                           ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                             const char *const message,
                                                             ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                            ByteBuffer message,
                                                            ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                                ByteBuffer message,
                                                                ExternError *err);

int32_t bbs_verify_blind_commitment_context_set_proof(uint64_t handle,
                                                      ByteBuffer proof,
                                                      ExternError *err);

uint64_t bbs_verify_blind_commitment_context_init(ExternError *err);

int32_t bbs_verify_blind_commitment_context_finish(uint64_t handle, ExternError *err);

int32_t bbs_verify_proof_context_finish(uint64_t handle, ExternError *err);


int32_t bbs_verify_proof_context_set_proof(uint64_t handle,
                                           ByteBuffer proof,
                                           ExternError *err);

int32_t bbs_verify_proof_context_set_public_key(uint64_t handle,
                                                ByteBuffer public_key,
                                                ExternError *err);


int32_t bbs_verify_proof_context_set_nonce_string(uint64_t handle,
                                                  const char *const message,
                                                  ExternError *err);

int32_t bbs_verify_proof_context_set_nonce_bytes(uint64_t handle,
                                                 ByteBuffer message,
                                                 ExternError *err);

int32_t bbs_verify_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     ByteBuffer message,
                                                     ExternError *err);


int32_t bbs_verify_proof_context_add_message_string(uint64_t handle,
                                                    uint32_t index,
                                                    const char *const message,
                                                    ExternError *err);

int32_t bbs_verify_proof_context_add_message_bytes(uint64_t handle,
                                                   uint32_t index,
                                                   ByteBuffer message,
                                                   ExternError *err);

int32_t bbs_verify_proof_context_add_message_prehashed(uint64_t handle,
                                                       uint32_t index,
                                                       ByteBuffer message,
                                                       ExternError *err);

uint64_t bbs_verify_proof_context_init(ExternError *err);

int32_t bls_generate_key(ByteBuffer seed,
                         ByteBuffer *public_key,
                         ByteBuffer *secret_key,
                         ExternError *err);

int32_t bls_get_public_key(ByteBuffer secret_key ,
                           ByteBuffer *public_key,
                           ExternError *err);

int32_t bls_public_key_size(void);

int32_t bls_public_key_to_bbs_key(ByteBuffer d_public_key,
                                  uint32_t message_count,
                                  ByteBuffer *public_key,
                                  ExternError *err);

int32_t bls_secret_key_size(void);

int32_t bls_secret_key_to_bbs_key(ByteBuffer secret_key,
                                  uint32_t message_count,
                                  ByteBuffer *public_key,
                                  ExternError *err);
#ifdef __cplusplus
} // extern "C"
#endif

#endif
