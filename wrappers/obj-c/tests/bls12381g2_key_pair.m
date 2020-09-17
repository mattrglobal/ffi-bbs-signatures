#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_signatures.h"
#import "../bbs-signatures/bbs.h"

@interface Bls12381G2KeyPairTests : XCTestCase

@end

@implementation Bls12381G2KeyPairTests

- (void)testGetPublicKeySize {
    //TODO need to rename this to G2
    XCTAssertEqual(bls_public_key_size(), 96);
}

- (void)testGetSecretKeySize {
    XCTAssertEqual(bls_secret_key_size(), 32);
}

- (void)testGenerateKeyPairWithSeed {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"YoASulEi3WV7yfJ+yWctJRCbHfr7WjK7JjcMrRqbL6E=" options:0];
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed: seed withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);
}

- (void)testGenerateKeyPairWithoutSeed {
    NSData *seed = NULL;
    NSError *error = nil;
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed: seed withError:&error];
    
    XCTAssertEqual(keyPair.publicKey.length, 96);
    XCTAssertEqual(keyPair.secretKey.length, 32);
}
@end
