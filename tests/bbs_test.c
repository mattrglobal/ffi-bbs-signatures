//
// Created by Michael Lodder on 6/6/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bbs.h"


int main(int argc, char** argv) {
    const int message_count = 5;
    ByteBuffer* seed;
    ByteBuffer* d_public_key;
    ByteBuffer* public_key;
    ByteBuffer* secret_key;
    ByteBuffer** messages;
    ByteBuffer* message;
    ByteBuffer* signature;
    ByteBuffer* nonce;
    ByteBuffer* commitment;
    ByteBuffer* blind_sign_context;
    ByteBuffer* blinding_factor;
    ByteBuffer* blind_signature;
    ByteBuffer* unblind_signature;
    ByteBuffer* proof;
    ExternError* err;
    signature_proof_status result;
    uint64_t handle;
    int i;

    seed = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    d_public_key = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    public_key = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    secret_key = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    messages = (ByteBuffer**) malloc(message_count * sizeof(ByteBuffer*));
    signature = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    nonce = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    commitment = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    blind_sign_context = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    blinding_factor = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    blind_signature = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    unblind_signature = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    proof = (ByteBuffer*) malloc(sizeof(ByteBuffer));
    err = (ExternError*) malloc(sizeof(ExternError));

    nonce->len = 16;
    nonce->data = (uint8_t *)malloc(60);
    memset(nonce->data, 15, 16);

    printf("Create key pair...");
    fflush(stdout);

    if (bls_generate_key(*seed, d_public_key, secret_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Public key is correct size...");
    fflush(stdout);
    if (d_public_key->len != bls_public_key_size()) {
        printf("fail\n");
        printf("    Expected %d, Found: %lld\n", bls_public_key_size(), d_public_key->len);
        goto Exit;
    }
    printf("pass\n");

    printf("Secret key is correct size...");
    fflush(stdout);
    if (secret_key->len != bls_secret_key_size()) {
        printf("fail\n");
        printf("Expected %d, Found: %lld\n", bls_secret_key_size(), secret_key->len);
        goto Exit;
    }
    printf("pass\n");

    printf("Create BBS key from BLS key that can sign %d messages...", message_count);
    fflush(stdout);
    if (bls_public_key_to_bbs_key(*d_public_key, message_count, public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    for (i = 0; i < message_count; i++) {
        message = (ByteBuffer*) malloc(sizeof(ByteBuffer));
        message->len = 10;
        message->data = (uint8_t *)malloc(10);
        memset(message->data, i+1, 10);
        messages[i] = message;
    }

    printf("Create sign context...");
    fflush(stdout);
    handle = bbs_sign_context_init(err);

    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in sign context...");
    fflush(stdout);
    if (bbs_sign_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set secret key in sign context...");
    fflush(stdout);
    if (bbs_sign_context_set_secret_key(handle, *secret_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages sign context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++) {
        if (bbs_sign_context_add_message_bytes(handle, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Sign %d messages ...", message_count);
    fflush(stdout);
    if (bbs_sign_context_finish(handle, signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Signature is correct size...");
    if (signature->len != bbs_blind_signature_size()) {
        printf("fail\n");
        printf("Expected %d, found %lld\n", bbs_blind_signature_size(), signature->len);
        goto Exit;
    }
    printf("pass\n");

    printf("Create blind commitment context...");
    fflush(stdout);
    handle = bbs_blind_commitment_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages to commitment...");
    fflush(stdout);
    if (bbs_blind_commitment_context_add_message_bytes(handle, 0, *messages[0], err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in blind sign commitment...");
    fflush(stdout);
    if (bbs_blind_commitment_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in blind sign commitment...");
    fflush(stdout);
    if (bbs_blind_commitment_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Get blind sign commitment...");
    fflush(stdout);
    if (bbs_blind_commitment_context_finish(handle, commitment, blind_sign_context, blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create verify blind signing commitment...");
    fflush(stdout);
    handle = bbs_verify_blind_commitment_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Add blinded index...");
    fflush(stdout);
    if (bbs_verify_blind_commitment_context_add_blinded(handle, 0, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in verify blind sign context...");
    fflush(stdout);
    if (bbs_verify_blind_commitment_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in verify blind sign context...");
    fflush(stdout);
    if (bbs_verify_blind_commitment_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set proof in verify blind sign context...");
    fflush(stdout);
    if (bbs_verify_blind_commitment_context_set_proof(handle, *blind_sign_context, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verify blind sign context...");
    fflush(stdout);
    result = bbs_verify_blind_commitment_context_finish(handle, err);

    switch(result) {
        case Success:
            printf("pass\n");
            break;
        case BadSignature:
            printf("fail.  Bad signature was used.\n");
            goto Fail;
        case BadHiddenMessage:
            printf("fail.  Bad hidden message was used.\n");
            goto Fail;
        case BadRevealedMessage:
            printf("fail. A message that wasn't signed was used.\n");
            goto Fail;
        default:
            printf("fail. Status = %d\n", result);
            goto Fail;
    }

    printf("Create blind signing context...");
    fflush(stdout);
    handle = bbs_blind_sign_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages blind sign context...");
    fflush(stdout);
    for (i = 1; i < message_count; i++) {
        if (bbs_blind_sign_context_add_message_bytes(handle, i, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Set public key in blind sign context...");
    fflush(stdout);
    if (bbs_blind_sign_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set secret key in blind sign context...");
    fflush(stdout);
    if (bbs_blind_sign_context_set_secret_key(handle, *secret_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set commitment in blind sign context...");
    fflush(stdout);
    if (bbs_blind_sign_context_set_commitment(handle, *commitment, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Creating blind signature...");
    fflush(stdout);
    if (bbs_blind_sign_context_finish(handle, blind_signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Unblinding signature...");
    fflush(stdout);
    if (bbs_unblind_signature(*blind_signature, *blinding_factor, unblind_signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create new verify signature context...");
    fflush(stdout);
    handle = bbs_verify_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set messages in verify signature context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++) {
        if (bbs_verify_context_add_message_bytes(handle, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Set public key in verify signature context...");
    fflush(stdout);
    if (bbs_verify_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set signature in verify signature context...");
    fflush(stdout);
    if (bbs_verify_context_set_signature(handle, *unblind_signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verifying signature...");
    fflush(stdout);
    if (bbs_verify_context_finish(handle, err) != 1) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create new proof context...");
    fflush(stdout);
    handle = bbs_create_proof_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding messages to proof context...");
    fflush(stdout);
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[0], Revealed, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[1], Revealed, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    for (i = 2; i < message_count; i++) {
        if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[i], HiddenProofSpecificBlinding, *blinding_factor, err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Setting signature in proof context...");
    fflush(stdout);
    if (bbs_create_proof_context_set_signature(handle, *unblind_signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in proof context...");
    fflush(stdout);
    if (bbs_create_proof_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in proof context...");
    fflush(stdout);
    if (bbs_create_proof_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Creating proof...");
    fflush(stdout);
    if (bbs_create_proof_context_finish(handle, proof, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create verify proof context...");
    fflush(stdout);
    handle = bbs_verify_proof_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding revealed messages to verify proof context...");
    fflush(stdout);
    for (i = 0; i < 2; i++) {
        if (bbs_verify_proof_context_add_message_bytes(handle, i, *messages[i], err) != 0) {
            printf("fail\n");
            goto Fail;
        }
    }
    printf("pass\n");

    printf("Set proof in verify proof context...");
    fflush(stdout);
    if (bbs_verify_proof_context_set_proof(handle, *proof, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in verify proof context...");
    fflush(stdout);
    if (bbs_verify_proof_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in verify proof context..");
    fflush(stdout);
    if (bbs_verify_proof_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verify blind sign context...");
    fflush(stdout);
    result = bbs_verify_proof_context_finish(handle, err);

    switch(result) {
        case Success:
            printf("pass\n");
            break;
        case BadSignature:
            printf("fail.  Bad signature was used.\n");
            goto Fail;
        case BadHiddenMessage:
            printf("fail.  Bad hidden message was used.\n");
            goto Fail;
        case BadRevealedMessage:
            printf("fail. A message that wasn't signed was used.\n");
            goto Fail;
        default:
            printf("fail. Status = %d\n", result);
            goto Fail;
    }

    printf("Create new proof context 2...");
    fflush(stdout);
    handle = bbs_create_proof_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding messages to proof context 2...");
    fflush(stdout);
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[0], HiddenProofSpecificBlinding, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[1], Revealed, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[2], HiddenProofSpecificBlinding, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[3], Revealed, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_create_proof_context_add_proof_message_bytes(handle, *messages[4], HiddenProofSpecificBlinding, *blinding_factor, err) != 0) {
        printf("fail\n");
        goto Fail;
    }

    printf("pass\n");

    printf("Setting signature in proof context 2...");
    fflush(stdout);
    if (bbs_create_proof_context_set_signature(handle, *unblind_signature, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in proof context 2...");
    fflush(stdout);
    if (bbs_create_proof_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in proof context 2...");
    fflush(stdout);
    if (bbs_create_proof_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Creating proof 2...");
    fflush(stdout);
    if (bbs_create_proof_context_finish(handle, proof, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Create verify proof context 2...");
    fflush(stdout);
    handle = bbs_verify_proof_context_init(err);
    if (handle == 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Adding revealed messages to verify proof context 2...");
    fflush(stdout);
    if (bbs_verify_proof_context_add_message_bytes(handle, 1, *messages[1], err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    if (bbs_verify_proof_context_add_message_bytes(handle, 3, *messages[3], err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set proof in verify proof context 2...");
    fflush(stdout);
    if (bbs_verify_proof_context_set_proof(handle, *proof, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set public key in verify proof context 2...");
    fflush(stdout);
    if (bbs_verify_proof_context_set_public_key(handle, *public_key, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Set nonce in verify proof context 2...");
    fflush(stdout);
    if (bbs_verify_proof_context_set_nonce_bytes(handle, *nonce, err) != 0) {
        printf("fail\n");
        goto Fail;
    }
    printf("pass\n");

    printf("Verify blind sign context 2...");
    fflush(stdout);
    result = bbs_verify_proof_context_finish(handle, err);

    switch(result) {
        case Success:
            printf("pass\n");
            break;
        case BadSignature:
            printf("fail.  Bad signature was used.\n");
            goto Fail;
        case BadHiddenMessage:
            printf("fail.  Bad hidden message was used.\n");
            goto Fail;
        case BadRevealedMessage:
            printf("fail. A message that wasn't signed was used.\n");
            goto Fail;
        default:
            printf("fail. Status = %d\n", result);
            goto Fail;
    }

    printf("Tests Passed\n");

    goto Exit;
Fail:
    printf("Error Message = %s\n", err->message);
    printf("Tests Failed\n");
Err:
    free(err->message);
Exit:
    bbs_byte_buffer_free(*seed);
    bbs_byte_buffer_free(*d_public_key);
    bbs_byte_buffer_free(*public_key);
    bbs_byte_buffer_free(*secret_key);
    bbs_byte_buffer_free(*signature);
    for (i = 0; i < message_count; i++) {
        bbs_byte_buffer_free(*messages[i]);
        free(messages[i]);
    }
    bbs_byte_buffer_free(*nonce);
    bbs_byte_buffer_free(*commitment);
    bbs_byte_buffer_free(*blind_sign_context);
    bbs_byte_buffer_free(*blinding_factor);
    bbs_byte_buffer_free(*blind_signature);
    bbs_byte_buffer_free(*proof);
    free(nonce);
    free(proof);
    free(signature);
    free(blind_signature);
    free(err);
    free(seed);
    free(d_public_key);
    free(public_key);
    free(secret_key);
    free(commitment);
    free(blind_sign_context);
    free(blinding_factor);
}
