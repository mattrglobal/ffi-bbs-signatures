#ifndef bbs_h
#define bbs_h

#include <stdint.h>

/* Used for receiving a bbs_signature_byte_buffer_t from C that was allocated by either C or Rust.
*  If Rust allocated, then the outgoing struct is `ffi_support::bbs_signature_byte_buffer_t`
*  Caller is responsible for calling free where applicable.
*/
typedef struct {
    int64_t len;
    uint8_t *_Nonnull data;
} bbs_signature_byte_buffer_t;

typedef struct {
    int32_t code;
    char *_Nullable message; /* note: nullable */
} bbs_signature_error_t;

typedef enum {
    Revealed = 1,
    HiddenProofSpecificBlinding = 2,
    HiddenExternalBlinding = 3,
} bbs_signature_proof_message_t;

typedef enum {
    /* The proof verified */
    Success = 200,
    /* The proof failed because the signature proof of knowledge failed */
    BadSignature = 400,
    /* The proof failed because a hidden message was invalid when the proof was created */
    BadHiddenMessage = 401,
    /* The proof failed because a revealed message was invalid */
    BadRevealedMessage = 402,
} bbs_signature_proof_status;

#ifdef __cplusplus
extern "C" {
#endif

void bbs_string_free(char *_Nullable string);
void bbs_byte_buffer_free(bbs_signature_byte_buffer_t data);

uint64_t bbs_blind_commitment_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_finish(uint64_t handle,
                                            bbs_signature_byte_buffer_t *_Nullable commitment,
                                            bbs_signature_byte_buffer_t *_Nullable out_context,
                                            bbs_signature_byte_buffer_t *_Nullable blinding_factor,
                                            bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_add_message_string(uint64_t handle,
                                                        uint32_t index,
                                                        const char *_Nullable const message,
                                                        bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_add_message_bytes(uint64_t handle,
                                                       uint32_t index,
                                                       bbs_signature_byte_buffer_t message,
                                                       bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_add_message_prehashed(uint64_t handle,
                                                           uint32_t index,
                                                           bbs_signature_byte_buffer_t message,
                                                           bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_set_public_key(uint64_t handle,
                                                    bbs_signature_byte_buffer_t public_key,
                                                    bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                      const char *_Nullable const message,
                                                      bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                     bbs_signature_byte_buffer_t message,
                                                     bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                         bbs_signature_byte_buffer_t message,
                                                         bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_finish(uint64_t handle,
                                      bbs_signature_byte_buffer_t *_Nullable blinded_signature,
                                      bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_add_message_string(uint64_t handle,
                                                  uint32_t index,
                                                  const char *_Nullable const message,
                                                  bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_add_message_bytes(uint64_t handle,
                                                 uint32_t index,
                                                 bbs_signature_byte_buffer_t message,
                                                 bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_add_message_prehashed(uint64_t handle,
                                                     uint32_t index,
                                                     bbs_signature_byte_buffer_t message,
                                                     bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_set_secret_key(uint64_t handle,
                                              bbs_signature_byte_buffer_t secret_key,
                                              bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_set_public_key(uint64_t handle,
                                              bbs_signature_byte_buffer_t public_key,
                                              bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_sign_context_set_commitment(uint64_t handle,
                                              bbs_signature_byte_buffer_t public_key ,
                                              bbs_signature_error_t *_Nullable err);

uint64_t bbs_blind_sign_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_blind_signature_size(void);

int32_t bbs_unblind_signature(bbs_signature_byte_buffer_t blind_signature,
                              bbs_signature_byte_buffer_t blinding_factor,
                              bbs_signature_byte_buffer_t *_Nullable unblind_signature,
                              bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_finish(uint64_t handle, bbs_signature_byte_buffer_t *_Nullable proof, bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_set_public_key(uint64_t handle,
                                                bbs_signature_byte_buffer_t public_key,
                                                bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_set_signature(uint64_t handle,
                                               bbs_signature_byte_buffer_t signature ,
                                               bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_set_nonce_string(uint64_t handle,
                                                  const char *_Nullable const message ,
                                                  bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_set_nonce_bytes(uint64_t handle,
                                                 bbs_signature_byte_buffer_t message,
                                                 bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     bbs_signature_byte_buffer_t message,
                                                     bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_add_proof_message_string(uint64_t handle,
                                                          const char *_Nullable const message,
                                                          bbs_signature_proof_message_t xtype,
                                                          bbs_signature_byte_buffer_t blinding_factor,
                                                          bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_add_proof_message_bytes(uint64_t handle,
                                                         bbs_signature_byte_buffer_t message,
                                                         bbs_signature_proof_message_t xtype,
                                                         bbs_signature_byte_buffer_t blinding_factor,
                                                         bbs_signature_error_t *_Nullable err);

int32_t bbs_create_proof_context_add_proof_message_prehashed(uint64_t handle,
                                                             bbs_signature_byte_buffer_t message,
                                                             bbs_signature_proof_message_t xtype,
                                                             bbs_signature_byte_buffer_t blinding_factor,
                                                             bbs_signature_error_t *_Nullable err);

uint64_t bbs_create_proof_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_add_message_string(uint64_t handle,
                                            const char *_Nullable const message,
                                            bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_add_message_bytes(uint64_t handle,
                                           bbs_signature_byte_buffer_t message,
                                           bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_add_message_prehashed(uint64_t handle,
                                               bbs_signature_byte_buffer_t message,
                                               bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_set_secret_key(uint64_t handle,
                                        bbs_signature_byte_buffer_t secret_key,
                                        bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_set_public_key(uint64_t handle,
                                        bbs_signature_byte_buffer_t public_key,
                                        bbs_signature_error_t *_Nullable err);

int32_t bbs_sign_context_finish(uint64_t handle, bbs_signature_byte_buffer_t *_Nullable signature, bbs_signature_error_t *_Nullable err);

uint64_t bbs_sign_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_signature_size(void);

int32_t bbs_verify_context_add_message_bytes(uint64_t handle,
                                             bbs_signature_byte_buffer_t message,
                                             bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_context_add_message_prehashed(uint64_t handle,
                                                 bbs_signature_byte_buffer_t message,
                                                 bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_context_add_message_string(uint64_t handle,
                                              const char *_Nullable const message,
                                              bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_context_set_public_key(uint64_t handle,
                                          bbs_signature_byte_buffer_t public_key,
                                          bbs_signature_error_t *_Nullable err);
int32_t bbs_verify_context_set_signature(uint64_t handle,
                                         bbs_signature_byte_buffer_t signature,
                                         bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_context_finish(uint64_t handle, bbs_signature_error_t *_Nullable err);

uint64_t bbs_verify_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_add_blinded(uint64_t handle,
                                                        uint32_t index,
                                                        bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_set_public_key(uint64_t handle,
                                                           bbs_signature_byte_buffer_t public_key,
                                                           bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                             const char *_Nullable const message,
                                                             bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                            bbs_signature_byte_buffer_t message,
                                                            bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                                bbs_signature_byte_buffer_t message,
                                                                bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_set_proof(uint64_t handle,
                                                      bbs_signature_byte_buffer_t proof,
                                                      bbs_signature_error_t *_Nullable err);

uint64_t bbs_verify_blind_commitment_context_init(bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_blind_commitment_context_finish(uint64_t handle, bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_add_revealed_index(uint64_t handle,
                                                    uint32_t index,
                                                    bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_finish(uint64_t handle, bbs_signature_error_t *_Nullable err);


int32_t bbs_verify_proof_context_set_proof(uint64_t handle,
                                           bbs_signature_byte_buffer_t proof,
                                           bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_set_public_key(uint64_t handle,
                                                bbs_signature_byte_buffer_t public_key,
                                                bbs_signature_error_t *_Nullable err);


int32_t bbs_verify_proof_context_set_nonce_string(uint64_t handle,
                                                  const char *_Nullable const message,
                                                  bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_set_nonce_bytes(uint64_t handle,
                                                 bbs_signature_byte_buffer_t message,
                                                 bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     bbs_signature_byte_buffer_t message,
                                                     bbs_signature_error_t *_Nullable err);


int32_t bbs_verify_proof_context_add_message_string(uint64_t handle,
                                                    const char *_Nullable const message,
                                                    bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_add_message_bytes(uint64_t handle,
                                                   bbs_signature_byte_buffer_t message,
                                                   bbs_signature_error_t *_Nullable err);

int32_t bbs_verify_proof_context_add_message_prehashed(uint64_t handle,
                                                       bbs_signature_byte_buffer_t message,
                                                       bbs_signature_error_t *_Nullable err);

uint64_t bbs_verify_proof_context_init(bbs_signature_error_t *_Nullable err);

int32_t bls_generate_g2_key(bbs_signature_byte_buffer_t seed,
                         bbs_signature_byte_buffer_t *_Nullable public_key,
                         bbs_signature_byte_buffer_t *_Nullable secret_key,
                         bbs_signature_error_t *_Nullable err);

int32_t bls_get_public_key(bbs_signature_byte_buffer_t secret_key ,
                           bbs_signature_byte_buffer_t *_Nullable public_key,
                           bbs_signature_error_t *_Nullable err);

int32_t bls_public_key_g2_size(void);

int32_t bls_public_key_to_bbs_key(bbs_signature_byte_buffer_t d_public_key,
                                  uint32_t message_count,
                                  bbs_signature_byte_buffer_t *_Nullable public_key,
                                  bbs_signature_error_t *_Nullable err);

int32_t bls_secret_key_size(void);

int32_t bls_secret_key_to_bbs_key(bbs_signature_byte_buffer_t secret_key,
                                  uint32_t message_count,
                                  bbs_signature_byte_buffer_t *_Nullable public_key,
                                  bbs_signature_error_t *_Nullable err);

int32_t bbs_get_total_messages_count_for_proof(bbs_signature_byte_buffer_t proof);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* bbs_h */
