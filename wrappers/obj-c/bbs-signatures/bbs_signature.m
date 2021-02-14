#import <Foundation/Foundation.h>

#import "bbs_signature.h"
#import "BbsSignatureError.h"

/** @brief BBS Signature */
@interface BbsSignature ()

/** @brief signature */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief BBS Signature */
@implementation BbsSignature

/**
* @brief Creates a BBS signature from the raw bytes
*/
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/**
* @brief Creates a BBS signature
*/
- (nullable instancetype)sign:(BbsKeyPair* _Nonnull)keyPair
                     messages:(NSArray* _Nonnull)messages
                    withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createSignature:keyPair
                 messages:messages
                withError:errorPtr];
    return self;
}

/**
* @Verifies the BBS signature
*/
- (bool)verify:(BbsKeyPair* _Nonnull)keyPair
      messages:(NSArray* _Nonnull)messages
     withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignature:keyPair
                        messages:messages
                       withError:errorPtr];
}

/**
* @brief Creates a BBS signature from a BLS12-381 G2 key pair
*/
- (nullable instancetype)blsSign:(Bls12381G2KeyPair* _Nonnull)keyPair
                        messages:(NSArray* _Nonnull)messages
                       withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createSignatureFromBls12381G2:keyPair
                               messages:messages
                              withError:errorPtr];
    return self;
}

/**
* @Verifies the BBS signature from a BLS12-381 G2 key pair
*/
- (bool)blsVerify:(Bls12381G2KeyPair* _Nonnull)keyPair
         messages:(NSArray* _Nonnull)messages
        withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignatureFromBlsKeyPair:keyPair
                                      messages:messages
                                     withError:errorPtr];
}

- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

- (bool)verifySignatureFromBlsKeyPair:(Bls12381G2KeyPair* _Nonnull)keyPair
                             messages:(NSArray* _Nonnull)messages
                            withError:(NSError* _Nullable*_Nullable)errorPtr {
    
    BbsKeyPair * bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                               messageCount:messages.count
                                                                  withError:errorPtr];
    
    if (*errorPtr != nil) {
        return false;
    }
    
    return [self verifySignature:bbsKeyPair
                        messages:messages
                       withError:errorPtr];
}

- (bool)verifySignature:(BbsKeyPair* _Nonnull)keyPair
               messages:(NSArray* _Nonnull)messages
              withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    uint64_t verifySignatureHandle = bbs_sign_context_init(err);
    
    if (verifySignatureHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    if (messages.count == 0){
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        if (bbs_verify_context_add_message_bytes(verifySignatureHandle, messageBuffer, err) != 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return false;
        }
    }
    
    bbs_signature_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = keyPair.publicKey.length;
    publicKeyBuffer.data = (uint8_t *)keyPair.publicKey.bytes;

    if (bbs_verify_context_set_public_key(verifySignatureHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    bbs_signature_byte_buffer_t signatureBuffer;
    signatureBuffer.len = self.value.length;
    signatureBuffer.data = (uint8_t *)self.value.bytes;

    if (bbs_verify_context_set_signature(verifySignatureHandle, signatureBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    if (bbs_verify_context_finish(verifySignatureHandle, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    free(err);
    return true;
}

- (void) createSignatureFromBls12381G2:(Bls12381G2KeyPair* _Nonnull)keyPair
                              messages:(NSArray* _Nonnull)messages
                             withError:(NSError* _Nullable*_Nullable)errorPtr {
    
    BbsKeyPair * bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                               messageCount:messages.count
                                                                  withError:errorPtr];
    
    if (*errorPtr != nil) {
        return;
    }
    
    [self createSignature:bbsKeyPair
                 messages:messages
                withError:errorPtr];
    return;
}

- (void) createSignature:(BbsKeyPair* _Nonnull)keyPair
                messages:(NSArray* _Nonnull)messages
               withError:(NSError* _Nullable*_Nullable)errorPtr {
    
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    uint64_t createSignatureHandle = bbs_sign_context_init(err);
    
    if (createSignatureHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        if (bbs_sign_context_add_message_bytes(createSignatureHandle, messageBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return;
        }
    }
    
    bbs_signature_byte_buffer_t secretKeyBuffer;
    secretKeyBuffer.len = keyPair.secretKey.length;
    secretKeyBuffer.data = (uint8_t *)keyPair.secretKey.bytes;

    if (bbs_sign_context_set_secret_key(createSignatureHandle, secretKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    bbs_signature_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = keyPair.publicKey.length;
    publicKeyBuffer.data = (uint8_t *)keyPair.publicKey.bytes;

    if (bbs_sign_context_set_public_key(createSignatureHandle, publicKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    bbs_signature_byte_buffer_t *signature = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    
    if (bbs_sign_context_finish(createSignatureHandle, signature, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    free(err);
    self.value = [[NSData alloc] initWithBytesNoCopy:signature->data
                                              length:(NSUInteger)signature->len
                                        freeWhenDone:true];
}

@end
