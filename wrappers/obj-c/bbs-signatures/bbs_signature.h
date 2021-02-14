#ifndef bbs_signature_h
#define bbs_signature_h

#include "bbs_key_pair.h"

/** @brief BBS Signature */
@interface BbsSignature : NSObject

/** @brief signature */
@property(nonatomic, readonly) NSData *_Nonnull value;

/**
* @brief Creates a BBS signature from the raw bytes
*/
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @brief Creates a BBS signature
*/
- (nullable instancetype)sign:(BbsKeyPair* _Nonnull)keyPair
                     messages:(NSArray* _Nonnull)messages
                    withError:(NSError*_Nullable*_Nullable)errorPtr;

/**
* @brief Creates a BBS signature from a BLS12-381 G2 key pair
*/
- (nullable instancetype)blsSign:(Bls12381G2KeyPair* _Nonnull)keyPair
                        messages:(NSArray* _Nonnull)messages
                       withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @Verifies the BBS signature
*/
- (bool)verify:(BbsKeyPair* _Nonnull)keyPair
      messages:(NSArray* _Nonnull)messages
     withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @Verifies the BBS signature from a BLS12-381 G2 key pair
*/
- (bool)blsVerify:(Bls12381G2KeyPair* _Nonnull)keyPair
         messages:(NSArray* _Nonnull)messages
        withError:(NSError *_Nullable*_Nullable)errorPtr;

@end

#endif /* bbs_signature_h */
