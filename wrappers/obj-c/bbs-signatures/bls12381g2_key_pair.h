#ifndef bls12381_key_pair_h
#define bls12381_key_pair_h

#import <Foundation/Foundation.h>
#import "bbs.h"

/** @brief BLS 12-381 G2 key pair */
@interface Bls12381G2KeyPair : NSObject

/** @brief secret key */
@property(nonatomic, readonly) NSData *_Nullable secretKey;

/** @brief public key */
@property(nonatomic, readonly) NSData *_Nonnull publicKey;

/**
* @brief initialise a BLS 12-381 G2 public key from data
*/
- (nullable instancetype)initFromPublicKey:(NSData* _Nonnull)data;

/**
* @brief initialise a BLS 12-381 G2 key pair by generating secretKey and publicKey
*/
- (nullable instancetype)initWithSeed:(NSData* _Nullable)seed withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @brief initialise a BLS 12-381 G2 key pair from the secretKey
*/
- (nullable instancetype)initWithSecretKey:(NSData* _Nonnull)secretKey withError:(NSError *_Nullable*_Nullable)errorPtr;

@end

#endif /* bls12381_key_pair_h */
