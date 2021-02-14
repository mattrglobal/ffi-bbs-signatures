#import "bls12381g2_key_pair.h"
#import "BbsSignatureError.h"

/** @brief BLS 12-381 G2 key pair */
@interface Bls12381G2KeyPair ()

/** @brief secret key */
@property(nonatomic, readwrite) NSData *secretKey;

/** @brief public key */
@property(nonatomic, readwrite) NSData *publicKey;

@end

@implementation Bls12381G2KeyPair

- (nullable instancetype)initWithPublicKey:(NSData* _Nonnull)publicKey {
    self.publicKey = [[NSData alloc] initWithData:publicKey];
    return self;
}

- (nullable instancetype)initWithSeed:(NSData* _Nullable)seed
                            withError:(NSError *_Nullable*_Nullable)errorPtr {
    [self generateKeyPair: seed withError:errorPtr];
    return self;
}

- (nullable instancetype)initWithSecretKey:(NSData* _Nonnull)secretKey
                                 withError:(NSError *_Nullable*_Nullable)errorPtr {
    [self keyPairFromSecretKey: secretKey withError:errorPtr];
    return self;
}

- (void) generateKeyPair:(NSData* _Nullable)seed
               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    bbs_signature_byte_buffer_t seedBuffer;
    if (seed != nil) {
        seedBuffer.len = seed.length;
        seedBuffer.data = (uint8_t *)seed.bytes;
    }
    else {
        seedBuffer.len = 0;
    }
    
    bbs_signature_byte_buffer_t *publicKey = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    bbs_signature_byte_buffer_t *secretKey = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));

    uint64_t handle = bls_generate_g2_key(seedBuffer, publicKey, secretKey, err);
    
    if (handle > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:publicKey->data length:(NSUInteger)publicKey->len freeWhenDone:true];
    self.secretKey = [[NSData alloc] initWithBytesNoCopy:secretKey->data length:(NSUInteger)secretKey->len freeWhenDone:true];
    
    free(err);
}

- (void) keyPairFromSecretKey:(NSData* _Nonnull)secretKey
                    withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    bbs_signature_byte_buffer_t secretKeyBuffer;
    secretKeyBuffer.len = secretKey.length;
    secretKeyBuffer.data = (uint8_t *)secretKey.bytes;
    
    //TODO handle when pointer is 0 e.g memory allocation failed
    bbs_signature_byte_buffer_t *publicKey = (bbs_signature_byte_buffer_t*) malloc(sizeof(bbs_signature_byte_buffer_t));
    bbs_signature_error_t *err = (bbs_signature_error_t*) malloc(sizeof(bbs_signature_error_t));
    
    if (bls_get_public_key(secretKeyBuffer, publicKey, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:publicKey->data length:(NSUInteger)publicKey->len freeWhenDone:true];
    self.secretKey = [[NSData alloc] initWithData:secretKey];
    
    free(err);
}
@end
