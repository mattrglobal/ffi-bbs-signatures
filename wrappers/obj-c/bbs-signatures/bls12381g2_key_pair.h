#ifndef bls12381g2_key_pair_h
#define bls12381g2_key_pair_h

#import <Foundation/Foundation.h>
#import "bbs.h"

/** @brief BLS 12-381 G2 key pair */
@interface Bls12381G2KeyPair : NSObject

/** @brief secret key */
@property(nonatomic, readonly) NSData *_Nullable secretKey;

/** @brief public key */
@property(nonatomic, readonly) NSData *_Nonnull publicKey;

/**
* @brief Initialises a BLS 12-381 G2 public key from the raw bytes of the public key
*/
- (nullable instancetype)initWithPublicKey:(NSData* _Nonnull)data;

/**
* @brief Generates a new BLS 12-381 G2 key pair by using an optionally supplied seed
*/
- (nullable instancetype)initWithSeed:(NSData* _Nullable)seed
                            withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @brief initialise a BLS 12-381 G2 key pair  from the raw bytes of the secretKey
*/
- (nullable instancetype)initWithSecretKey:(NSData* _Nonnull)secretKey
                                 withError:(NSError *_Nullable*_Nullable)errorPtr;

@end

#endif /* bls12381g2_key_pair_h */
