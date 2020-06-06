//
// Created by Michael Lodder on 6/6/20.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bbs.h"


int main(int argc, char** argv) {
    const int message_count = 5;
    struct ByteBuffer* seed;
    struct ByteBuffer* d_public_key;
    struct ByteBuffer* public_key;
    struct ByteBuffer* secret_key;
    struct ByteBuffer** messages;
    struct ByteBuffer* message;
    struct ByteBuffer* signature;
    struct ExternError* err;
    uint64_t handle;
    int i;

    seed = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
    d_public_key = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
    public_key = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
    secret_key = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
    messages = (struct ByteBuffer**) malloc(message_count * sizeof(struct ByteBuffer*));
    signature = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
    err = (struct ExternError*) malloc(sizeof(struct ExternError));

    printf("Create key pair...");
    fflush(stdout);

    if (bls_generate_key(seed, d_public_key, secret_key, err) != 0) {
        printf("fail\n");
        goto Err;
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
    if (bls_public_key_to_bbs_key(d_public_key, message_count, public_key, err) != 0) {
        printf("fail\n");
        goto Err;
    }
    printf("pass\n");

    for (i = 0; i < message_count; i++) {
        message = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
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
        goto Err;
    }
    printf("pass\n");

    printf("Set public key in sign context...");
    fflush(stdout);
    if (bbs_sign_context_set_public_key(handle, public_key, err) != 0) {
        printf("fail\n");
        goto Err;
    }
    printf("pass\n");

    printf("Set secret key in sign context...");
    fflush(stdout);
    if (bbs_sign_context_set_secret_key(handle, secret_key, err) != 0) {
        printf("fail\n");
        goto Err;
    }
    printf("pass\n");

    printf("Set messages sign context...");
    fflush(stdout);
    for (i = 0; i < message_count; i++) {
        if (bbs_sign_context_add_message_bytes(handle, messages[i], err) != 0) {
            printf("fail\n");
            goto Err;
        }
    }
    printf("pass\n");

    printf("Sign %d messages ...", message_count);
    fflush(stdout);
    if (bbs_sign_context_finish(handle, signature, err) != 0) {
        printf("fail\n");
        goto Err;
    }
    printf("pass\n");

    printf("Signature is correct size...");
    if (signature->len != bbs_blind_signature_size()) {
        printf("fail\n");
        printf("Expected %d, found %lld\n", bbs_blind_signature_size(), signature->len);
        goto Exit;
    }
    printf("pass\n");

    printf("Tests Passed\n");

    goto Exit;
Fail:
    printf("%s\n", err->message);
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
    free(signature);
    free(err);
    free(seed);
    free(d_public_key);
    free(public_key);
    free(secret_key);
}
