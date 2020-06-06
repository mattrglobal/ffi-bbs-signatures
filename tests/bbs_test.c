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

    bls_generate_key(seed, d_public_key, secret_key, err);

    if (bls_public_key_to_bbs_key(d_public_key, message_count, public_key, err) != 0) {
        printf("%s\n", err->message);
        goto Err;
    }

    for (i = 0; i < message_count; i++) {
        message = (struct ByteBuffer*) malloc(sizeof(struct ByteBuffer));
        message->len = 10;
        message->data = (uint8_t *)malloc(10);
        memset(message->data, i+1, 10);
        messages[i] = message;
    }

    handle = bbs_sign_context_init(err);
    if (bbs_sign_context_set_public_key(handle, public_key, err) != 0) {
        printf("%s\n", err->message);
        goto Err;
    }

    if (bbs_sign_context_set_secret_key(handle, secret_key, err) != 0) {
        printf("%s\n", err->message);
        goto Err;
    }

    for (i = 0; i < message_count; i++) {
        if (bbs_sign_context_add_message_bytes(handle, messages[i], err) != 0) {
            printf("%s\n", err->message);
            goto Err;
        }
    }

    if (bbs_sign_context_finish(handle, signature, err) != 0) {
        printf("%s\n", err->message);
        goto Err;
    }

    for (i = 0; i < signature->len; i++) {
        printf("%d ", signature->data[i]);
    }


    goto Exit;
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
