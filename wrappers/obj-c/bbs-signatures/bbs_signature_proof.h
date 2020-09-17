#ifndef bbs_signature_proof_h
#define bbs_signature_proof_h

#import "bbs_signatures.h"

@interface BbsSignatureProof : NSObject

/** @brief signature */
@property(nonatomic, readonly) NSData *_Nonnull value;
/**
* @brief Creates a BBS signature proof from the raw bytes
*/
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @brief Creates a BBS signature proof
*/
- (nullable instancetype)createProof:(BbsSignature* _Nonnull)signature : (BbsKeyPair* _Nonnull)keyPair : (NSData* _Nonnull)nonce : (NSArray* _Nonnull)messages : (NSArray* _Nonnull)revealed withError:(NSError*_Nullable*_Nullable)errorPtr;

/**
* @brief Creates a BBS signature proof
*/
- (nullable instancetype)blsCreateProof:(BbsSignature* _Nonnull)signature : (Bls12381G2KeyPair* _Nonnull)keyPair : (NSData* _Nonnull)nonce : (NSArray* _Nonnull)messages : (NSArray* _Nonnull)revealed withError:(NSError*_Nullable*_Nullable)errorPtr;

/**
* @Verifies the BBS signature proof
*/
- (bool)verifyProof:(BbsKeyPair* _Nonnull)keyPair : (NSArray* _Nonnull)messages : (NSData* _Nonnull)nonce withError:(NSError *_Nullable*_Nullable)errorPtr;

/**
* @Verifies the BBS signature proof from a BLS12-381 G2 key pair
*/
- (bool)blsVerifyProof:(Bls12381G2KeyPair* _Nonnull)keyPair : (NSArray* _Nonnull)messages : (NSData* _Nonnull)nonce withError:(NSError *_Nullable*_Nullable)errorPtr;

@end

#endif /* bbs_signature_proof_h */
