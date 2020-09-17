#import <Foundation/Foundation.h>

#import "bbs_key_pair.h"
#import "BbsSignatureError.h"

/** @brief BBS+ key pair */
@interface BbsKeyPair ()

/** @brief secret key */
@property(nonatomic, readwrite) NSData *secretKey;

/** @brief public key */
@property(nonatomic, readwrite) NSData *publicKey;

/** @brief message count */
@property(nonatomic, readwrite) size_t messageCount;

@end

/** @brief Implementation of A BBS+ Key pair */
@implementation BbsKeyPair

- (nullable instancetype)initFromPublicKey:(NSData* _Nonnull)data : (size_t)messageCount {
    self.publicKey = data;
    self.messageCount = messageCount;
    return self;
}

/** @brief Initializes a BBS+ key pair from a BLS 12-381 G2 key pair*/
- (nullable instancetype)initFromBls12381G2KeyPair:(Bls12381G2KeyPair* _Nonnull)keyPair : (size_t)messageCount withError:(NSError *_Nullable*_Nullable)errorPtr {
    [self bls12381G2ToBbs: keyPair : messageCount withError:errorPtr];
    return self;
}

/** @brief Initializes a BBS+ public key from a BLS 12-381 G2 public key*/
- (nullable instancetype)initFromBls12381G2PublicKey:(NSData* _Nonnull)publicKey : (size_t)messageCount withError:(NSError *_Nullable*_Nullable)errorPtr {
    [self bls12381G2PublicKeyToBbsPublicKey: publicKey : messageCount withError:errorPtr];
    return self;
}

- (void) bls12381G2ToBbs:(Bls12381G2KeyPair* _Nonnull)keyPair : (size_t)messageCount withError:(NSError *_Nullable*_Nullable)errorPtr {
    bbs_signature_byte_buffer_t publicKey;
    publicKey.len = keyPair.publicKey.length;
    publicKey.data = (uint8_t *)keyPair.publicKey.bytes;
    
    bbs_signature_byte_buffer_t *bbsPublicKey = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    if (bls_public_key_to_bbs_key(publicKey, (uint32_t)messageCount, bbsPublicKey, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:bbsPublicKey->data length:(NSUInteger)bbsPublicKey->len freeWhenDone:true];
    self.secretKey = keyPair.secretKey;
    self.messageCount = messageCount;
    
    free(err);
}

- (void) bls12381G2PublicKeyToBbsPublicKey:(NSData* _Nonnull)publicKeyData : (size_t)messageCount withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    bbs_signature_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = publicKeyData.length;
    publicKeyBuffer.data = (uint8_t *)publicKeyData.bytes;
    
    bbs_signature_byte_buffer_t *publicKey = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    if (bls_public_key_to_bbs_key(publicKeyBuffer, (uint32_t)messageCount, publicKey, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:publicKey->data length:(NSUInteger)publicKey->len freeWhenDone:true];
    self.messageCount = messageCount;
    
    free(err);
}

@end
