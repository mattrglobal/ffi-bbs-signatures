#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_key_pair.h"

@interface BbsKeyPairTests : XCTestCase

@end

@implementation BbsKeyPairTests

- (void)testGenerateKeyPairFromBls12381G2KeyPair {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed: seed withError:&error];
    NSUInteger *messageCount = 10;
    
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                              messageCount:messageCount
                                                                 withError:&error];
    
    XCTAssertEqual(bbsKeyPair.secretKey.length, 32);
    XCTAssertEqual(bbsKeyPair.messageCount, 10);
}

- (void)testGeneratePublicKeyFromBls12381G2PublicKey {
    NSError *error = nil;
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    NSUInteger *messageCount = 10;
    
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:keyPair
                                                              messageCount:messageCount
                                                                 withError:&error];
    
    XCTAssertEqual(bbsKeyPair.secretKey, nil);
    XCTAssertEqual(bbsKeyPair.messageCount, 10);
    XCTAssertEqual(bbsKeyPair.publicKey.length, 628);
}
@end
