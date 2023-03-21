#include "bbs.h"

void shim_bbs_byte_buffer_free(struct ByteBuffer v);

int32_t shim_bbs_blind_commitment_context_add_message_string(uint64_t handle,
                                                        uint32_t index,
                                                        FfiStr message,
                                                        struct ExternError *err);

int32_t shim_bbs_blind_commitment_context_add_message_bytes(uint64_t handle,
                                                       uint32_t index,
                                                       struct ByteArray *message,
                                                       struct ExternError *err) {
    return bbs_blind_commitment_context_add_message_bytes(handle, index, *message, err);
}

int32_t shim_bbs_blind_commitment_context_add_message_prehashed(uint64_t handle,
                                                           uint32_t index,
                                                           struct ByteArray message,
                                                           struct ExternError *err);

int32_t shim_bbs_blind_commitment_context_set_public_key(uint64_t handle,
                                                    struct ByteArray *value,
                                                    struct ExternError *err) {

    return bbs_blind_commitment_context_set_public_key(handle, *value, err);
}

int32_t shim_bbs_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                      FfiStr message,
                                                      struct ExternError *err);

int32_t shim_bbs_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                     struct ByteArray *value,
                                                     struct ExternError *err) {

    return bbs_blind_commitment_context_set_nonce_bytes(handle, *value, err);
}

int32_t shim_bbs_blind_commitment_context_set_nonce_prehashed(uint64_t handle,
                                                         struct ByteArray value,
                                                         struct ExternError *err);


int32_t shim_bbs_blind_sign_context_add_message_string(uint64_t handle,
                                                  uint32_t index,
                                                  FfiStr message,
                                                  struct ExternError *err);

int32_t shim_bbs_blind_sign_context_add_message_prehashed(uint64_t handle,
                                                     uint32_t index,
                                                     struct ByteArray message,
                                                     struct ExternError *err);

int32_t shim_bbs_blind_sign_context_set_public_key(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_blind_sign_context_set_public_key(handle, *value, err);
}

int32_t shim_bbs_verify_context_set_public_key(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_verify_context_set_public_key(handle, *value, err);
}


int32_t shim_bbs_create_proof_context_set_public_key(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_create_proof_context_set_public_key(handle, *value, err);
}


int32_t shim_bbs_verify_proof_context_set_public_key(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_verify_proof_context_set_public_key(handle, *value, err);
}

int32_t shim_bbs_verify_proof_context_set_nonce_bytes(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_verify_proof_context_set_nonce_bytes(handle, *value, err);
}

int32_t shim_bbs_blind_sign_context_set_secret_key(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_blind_sign_context_set_secret_key(handle, *value, err);
}


int32_t shim_bbs_blind_sign_context_set_commitment(uint64_t handle,
                                              struct ByteArray *value,
                                              struct ExternError *err) {
    return bbs_blind_sign_context_set_commitment(handle, *value, err);

}

int32_t shim_bbs_unblind_signature(struct ByteArray *blind_signature,
                              struct ByteArray *blinding_factor,
                              struct ByteBuffer *unblind_signature,
                              struct ExternError *err) {

    return bbs_unblind_signature(*blind_signature, *blinding_factor, unblind_signature, err);
}


int32_t shim_bbs_create_proof_context_add_proof_message_string(uint64_t handle,
                                                          FfiStr message,
                                                          enum ProofMessageType xtype,
                                                          struct ByteArray blinding_factor,
                                                          struct ExternError *err);

int32_t shim_bbs_create_proof_context_add_proof_message_bytes(uint64_t handle,
                                                         struct ByteArray *message,
                                                         enum ProofMessageType xtype,
                                                         struct ByteArray *blinding_factor,
                                                         struct ExternError *err) {
    return bbs_create_proof_context_add_proof_message_bytes(handle, *message, xtype, *blinding_factor, err);
}

int32_t shim_bbs_verify_proof_context_add_message_bytes(uint64_t handle,
                                                         struct ByteArray *message,
                                                         struct ExternError *err) {
    return bbs_verify_proof_context_add_message_bytes(handle, *message, err);
}

int32_t shim_bbs_create_proof_context_add_proof_message_prehashed(uint64_t handle,
                                                             struct ByteArray *message,
                                                             enum ProofMessageType xtype,
                                                             struct ByteArray *blinding_factor,
                                                             struct ExternError *err);


int32_t shim_bbs_create_proof_context_set_nonce_string(uint64_t handle,
                                                  FfiStr message,
                                                  struct ExternError *err);

int32_t shim_bbs_create_proof_context_set_nonce_bytes(uint64_t handle,
                                                 struct ByteArray *value,
                                                 struct ExternError *err) {
    return bbs_create_proof_context_set_nonce_bytes(handle, *value, err);
}

int32_t shim_bbs_create_proof_context_set_nonce_prehashed(uint64_t handle,
                                                     struct ByteArray *value,
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

int32_t shim_bbs_sign_context_add_message_bytes(uint64_t handle,
                                           ByteArray *message,
                                           struct ExternError *err) {

    return bbs_sign_context_add_message_bytes(
        handle, *message, err
    );
}

int32_t shim_bbs_sign_context_add_message_prehashed(uint64_t handle,
                                               struct ByteArray *message,
                                               struct ExternError *err);


int32_t shim_bbs_blind_sign_context_finish(uint64_t handle,
                                      struct ByteBuffer **blinded_signature,
                                      struct ExternError *err) {


  *blinded_signature = malloc(sizeof(ByteBuffer));
return  bbs_blind_sign_context_finish(handle, *blinded_signature, err);

}

int32_t shim_bbs_sign_context_set_secret_key(uint64_t handle,
                                        struct ByteArray *value,
                                        struct ExternError *err) {

    return bbs_sign_context_set_secret_key(
        handle,
        *value,
        err
    );
}

int32_t shim_bbs_sign_context_set_public_key(uint64_t handle,
                                        struct ByteArray *value,
                                        struct ExternError *err) {

    return bbs_sign_context_set_public_key(
        handle, *value, err
    );
}


uint64_t bbs_verify_context_init(struct ExternError *err);

int32_t bbs_verify_context_add_message_string(uint64_t handle,
                                              FfiStr message,
                                              struct ExternError *err);

int32_t shim_bbs_verify_context_add_message_bytes(uint64_t handle,
                                             struct ByteArray *message,
                                             struct ExternError *err) {

    return bbs_verify_context_add_message_bytes(handle, *message, err);
}

int32_t shim_bbs_verify_context_add_message_prehashed(uint64_t handle,
                                                 struct ByteArray *message,
                                                 struct ExternError *err);

int32_t shim_bbs_verify_context_set_signature(uint64_t handle,
                                         struct ByteArray *value,
                                         struct ExternError *err) {
    return bbs_verify_context_set_signature(handle, *value, err);
}

int32_t shim_bbs_create_proof_context_set_signature(uint64_t handle,
                                         struct ByteArray *value,
                                         struct ExternError *err) {
    return bbs_create_proof_context_set_signature(handle, *value, err);
}

int32_t bbs_verify_context_finish(uint64_t handle, struct ExternError *err);

void free_verify_proof(uint64_t v, struct ExternError *err);

int32_t bbs_get_total_messages_count_for_proof(struct ByteArray proof);

uint64_t bbs_verify_proof_context_init(struct ExternError *err);

int32_t bbs_verify_proof_context_add_message_string(uint64_t handle,
                                                    FfiStr message,
                                                    struct ExternError *err);


int32_t bbs_verify_proof_context_add_message_prehashed(uint64_t handle,
                                                       struct ByteArray message,
                                                       struct ExternError *err);

int32_t shim_bbs_verify_proof_context_set_proof(uint64_t handle,
                                           struct ByteArray *value,
                                           struct ExternError *err) {
    return bbs_verify_proof_context_set_proof(handle, *value, err);
                                           }

void free_verify_sign_proof(uint64_t v, struct ExternError *err);


int32_t shim_bbs_verify_blind_commitment_context_set_public_key(uint64_t handle,
                                                           struct ByteArray *value,
                                                           struct ExternError *err) {
    return bbs_verify_blind_commitment_context_set_public_key(handle, *value, err);
}

int32_t shim_bbs_blind_sign_context_add_message_bytes(uint64_t handle,
                                                 uint32_t index,
                                                 struct ByteArray *message,
                                                 struct ExternError *err) {
    return bbs_blind_sign_context_add_message_bytes(handle, index, *message, err);
}

int32_t bbs_verify_blind_commitment_context_set_nonce_string(uint64_t handle,
                                                             FfiStr message,
                                                             struct ExternError *err);

int32_t shim_bbs_verify_blind_commitment_context_set_nonce_bytes(uint64_t handle,
                                                            struct ByteArray *value,
                                                            struct ExternError *err) {
    return bbs_verify_blind_commitment_context_set_nonce_bytes(handle, *value, err);
}

int32_t shim_bbs_verify_blind_commitment_context_set_proof(uint64_t handle,
                                                      struct ByteArray *value,
                                                      struct ExternError *err) {
    return bbs_verify_blind_commitment_context_set_proof(handle, *value, err);
}


int32_t shim_bls_generate_g2_key(struct ByteArray *seed,
                                    struct ByteBuffer *public_key,
                                    struct ByteBuffer *secret_key,
                                    struct ExternError *err) {

    return bls_generate_g2_key(
        *seed,
        public_key,
        secret_key,
        err
    );

}


int32_t shim_bls_generate_blinded_g2_key(ByteArray *seed,
                                    struct ByteBuffer *public_key,
                                    struct ByteBuffer *secret_key,
                                    struct ByteBuffer *blinding_factor,
                                    struct ExternError *err) {

    return bls_generate_blinded_g2_key(
        *seed,
        public_key,
        secret_key,
        blinding_factor,
        err
    );

}


int32_t shim_bls_public_key_to_bbs_key(struct ByteArray *d_public_key,
                                  uint32_t message_count,
                                  struct ByteBuffer *public_key,
                                  struct ExternError *err) {

    return bls_public_key_to_bbs_key(*d_public_key, message_count, public_key, err);

}


