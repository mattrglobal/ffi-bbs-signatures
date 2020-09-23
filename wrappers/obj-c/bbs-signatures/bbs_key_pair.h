#ifndef bbs_key_pair_h
#define bbs_key_pair_h

#import "bbs.h"
#import "bls12381g2_key_pair.h"

/** @brief BBS key pair */
@interface BbsKeyPair : NSObject

/** @brief secret key */
@property(nonatomic, readonly) NSData *_Nullable secretKey;

/** @brief public key */
@property(nonatomic, readonly) NSData *_Nonnull publicKey;

/** @brief message count */
@property(nonatomic, readonly) size_t messageCount;

/**
* @brief Initialises a BBS public key from the raw bytes of the public key
*/
- (nullable instancetype)initWithData:(NSData* _Nonnull)publicKey
                        messageCount:(size_t)messageCount;

/**
* @brief Initialises a BBS public key from the raw bytes of the public and secret key
*/
- (nullable instancetype)initWithData:(NSData* _Nonnull)publicKey
                         messageCount:(size_t)messageCount
                         andSecretKey:(NSData* _Nullable)secretKey;

/**
* @brief Initialises a BBS public key from a BLS 12-381 G2 key pair
*/
- (nullable instancetype)initWithBls12381G2KeyPair:(Bls12381G2KeyPair* _Nonnull)keyPair
                                  messageCount:(size_t)messageCount
                                         withError:(NSError *_Nullable*_Nullable)errorPtr;

@end

#endif /* bbs_key_pair_h */
