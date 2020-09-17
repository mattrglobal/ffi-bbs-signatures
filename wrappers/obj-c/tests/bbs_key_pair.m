#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_signatures.h"

@interface BbsKeyPairTests : XCTestCase

@end

@implementation BbsKeyPairTests

- (void)testGenerateKeyPairFromBls12381G2KeyPair {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed: seed withError:&error];
    NSUInteger *messageCount = 10;
    
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initFromBls12381G2KeyPair:keyPair:messageCount withError:&error];
    
    XCTAssertEqual(bbsKeyPair.secretKey.length, 32);
    XCTAssertEqual(bbsKeyPair.messageCount, 10);
}

- (void)testGeneratePublicKeyFromBls12381G2PublicKey {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed: seed withError:&error];
    NSUInteger *messageCount = 10;
    
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initFromBls12381G2PublicKey:keyPair.publicKey :messageCount withError:&error];
    
    XCTAssertEqual(bbsKeyPair.secretKey, nil);
    XCTAssertEqual(bbsKeyPair.messageCount, 10);
}
@end
