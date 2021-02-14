#import <Foundation/Foundation.h>

#import "bbs.h"
#import "bbs_signature_proof.h"
#import "BbsSignatureError.h"

@interface BbsSignatureProof ()

/** @brief A BBS Signature Proof */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief A BBS Signature Proof */
@implementation BbsSignatureProof

/** @brief Creates a BBS signature proof from the raw bytes  */
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/** @brief Creates a BBS signature proof */
- (nullable instancetype)createProof:(BbsSignature* _Nonnull)signature
                             keyPair:(BbsKeyPair* _Nonnull)keyPair
                               nonce:(NSData* _Nonnull)nonce
                            messages:(NSArray* _Nonnull)messages
                            revealed:(NSArray* _Nonnull)revealed
                           withError:(NSError*_Nullable*_Nullable)errorPtr {
    
    [self createSignatureProof:signature
                       keyPair:keyPair
                         nonce:nonce
                      messages:messages
                      revealed:revealed
                     withError:errorPtr];
    return self;
}

/** @brief Creates a BBS signature proof  from a BLS12-381G2 public key */
- (nullable instancetype)blsCreateProof:(BbsSignature* _Nonnull)signature
                                keyPair:(Bls12381G2KeyPair* _Nonnull)keyPair
                                  nonce:(NSData* _Nonnull)nonce
                               messages:(NSArray* _Nonnull)messages
                               revealed:(NSArray* _Nonnull)revealed
                              withError:(NSError*_Nullable*_Nullable)errorPtr {
    
    [self createSignatureProofFromBls12381G2:signature
                                     keyPair:keyPair
                                       nonce:nonce
                                    messages:messages
                                    revealed:revealed
                                   withError:errorPtr];
    return self;
}

/** @brief Initializes a key pair */
- (bool)verifyProof:(BbsKeyPair* _Nonnull)keyPair
           messages:(NSArray* _Nonnull)messages
              nonce:(NSData* _Nonnull)nonce
          withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignatureProof:keyPair
                             messages:messages
                                nonce:nonce
                            withError:errorPtr];
}

/** @brief Initializes a key pair */
- (bool)blsVerifyProof:(Bls12381G2KeyPair* _Nonnull)keyPair
              messages:(NSArray* _Nonnull)messages
                 nonce:(NSData* _Nonnull)nonce
             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignatureProofFromBls12381G2:keyPair
                                           messages:messages
                                              nonce:nonce
                                          withError:errorPtr];
}

/** @brief Initializes a key pair */
- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

- (void) createSignatureProof:(BbsSignature* _Nonnull)signature
                      keyPair:(BbsKeyPair* _Nonnull)keyPair
                        nonce:(NSData* _Nonnull)nonce
                     messages:(NSArray* _Nonnull)messages
                     revealed:(NSArray* _Nonnull)revealed
                    withError:(NSError*_Nullable*_Nullable)errorPtr {
    
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    uint64_t createProofHandle = bbs_create_proof_context_init(err);
    
    if (createProofHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    int i = 0;
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        bbs_signature_byte_buffer_t blindingFactor;
        blindingFactor.len = 0;
        
        Boolean isRevealed = [revealed containsObject:[[NSNumber alloc] initWithInt:i]];
        
        bbs_signature_proof_message_t messageRevealType;
        
        if (isRevealed) {
            messageRevealType = Revealed;
        }
        else {
            messageRevealType = HiddenProofSpecificBlinding;
        }
        
        if (bbs_create_proof_context_add_proof_message_bytes(createProofHandle, messageBuffer, messageRevealType, blindingFactor, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return;
        }
        
        i++;
    }
    
    bbs_signature_byte_buffer_t signatureBuffer;
    signatureBuffer.len = signature.value.length;
    signatureBuffer.data = (uint8_t *)signature.value.bytes;
    
    if (bbs_create_proof_context_set_signature(createProofHandle, signatureBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    bbs_signature_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = keyPair.publicKey.length;
    publicKeyBuffer.data = (uint8_t *)keyPair.publicKey.bytes;
    
    if (bbs_create_proof_context_set_public_key(createProofHandle, publicKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    bbs_signature_byte_buffer_t nonceBuffer;
    nonceBuffer.len = nonce.length;
    nonceBuffer.data = (uint8_t *)nonce.bytes;
    
    if (bbs_create_proof_context_set_nonce_bytes(createProofHandle, nonceBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    bbs_signature_byte_buffer_t *proof = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    
    if (bbs_create_proof_context_finish(createProofHandle, proof, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.value = [[NSData alloc] initWithBytesNoCopy:proof->data
                                              length:(NSUInteger)proof->len
                                        freeWhenDone:true];
    
    free(err);
}

- (void) createSignatureProofFromBls12381G2:(BbsSignature* _Nonnull)signature
                                    keyPair:(Bls12381G2KeyPair* _Nonnull)keyPair
                                      nonce:(NSData* _Nonnull)nonce
                                   messages:(NSArray* _Nonnull)messages
                                   revealed:(NSArray* _Nonnull)revealed
                                  withError:(NSError*_Nullable*_Nullable)errorPtr {
    
    BbsKeyPair * bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                               messageCount:messages.count
                                                                  withError:errorPtr];
    
    if (*errorPtr != nil) {
        return;
    }
    
    [self createSignatureProof:signature
                       keyPair:bbsKeyPair
                         nonce:nonce
                      messages:messages
                      revealed:revealed
                     withError:errorPtr];
    return;
}

/** @brief Initializes a key pair */
- (bool)verifySignatureProof:(BbsKeyPair* _Nonnull)keyPair
                    messages:(NSArray* _Nonnull)messages
                       nonce:(NSData* _Nonnull)nonce
                   withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    uint64_t verifyProofHandle = bbs_verify_proof_context_init(err);
    
    if (verifyProofHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
                
        if (bbs_verify_proof_context_add_message_bytes(verifyProofHandle, messageBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return false;
        }
    }
    
    bbs_signature_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = keyPair.publicKey.length;
    publicKeyBuffer.data = (uint8_t *)keyPair.publicKey.bytes;
    
    if (bbs_verify_proof_context_set_public_key(verifyProofHandle, publicKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    bbs_signature_byte_buffer_t nonceBuffer;
    nonceBuffer.len = nonce.length;
    nonceBuffer.data = (uint8_t *)nonce.bytes;
    
    if (bbs_verify_proof_context_set_nonce_bytes(verifyProofHandle, nonceBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    bbs_signature_byte_buffer_t proofBuffer;
    proofBuffer.len = self.value.length;
    proofBuffer.data = (uint8_t *)self.value.bytes;
    
    if (bbs_verify_proof_context_set_proof(verifyProofHandle, proofBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    if (bbs_verify_proof_context_finish(verifyProofHandle, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    return true;
}

/** @brief Initializes a key pair */
- (bool)verifySignatureProofFromBls12381G2:(Bls12381G2KeyPair* _Nonnull)keyPair
                                  messages:(NSArray* _Nonnull)messages
                                     nonce:(NSData* _Nonnull)nonce
                                 withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    int messageCount = [[BbsSignatureProof alloc] getMessagesCountFromProof:self.value];
    
    BbsKeyPair * bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                               messageCount:messageCount
                                                                  withError:errorPtr];
    
    if (*errorPtr != nil) {
        return false;
    }
    
    return [self verifySignatureProof:bbsKeyPair
                             messages:messages
                                nonce:nonce
                            withError:errorPtr];
}

- (int)getMessagesCountFromProof:(NSData* _Nonnull)proof {
    bbs_signature_byte_buffer_t proofBuffer;
    proofBuffer.len = proof.length;
    proofBuffer.data = (uint8_t *)proof.bytes;
    
    return bbs_get_total_messages_count_for_proof(proofBuffer);
}

@end
