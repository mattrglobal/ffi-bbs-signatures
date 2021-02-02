#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_key_pair.h"
#import "../bbs-signatures/bls12381g2_key_pair.h"
#import "../bbs-signatures/bbs.h"

@interface Bls12381G2KeyPairTests : XCTestCase

@end

@implementation Bls12381G2KeyPairTests

- (void)testGetPublicKeySize {
    XCTAssertEqual(bls_public_key_g2_size(), 96);
}

- (void)testGetSecretKeySize {
    XCTAssertEqual(bls_secret_key_size(), 32);
}

- (void)testGenerateKeyPairWithSeed {
    NSError *error = nil;
    NSData *expectedPublicKey = [[NSData alloc] initWithBase64EncodedString:@"pQro1uqpvUPM31sr+jHffz7+KJIpA3kFen4SoKATURRgo7pk582aaqIxSinWsgHDB9j9dwxYRbC3q2ZmICR2OVMX3FHW9LZV2QAauTYFn7gEra1BSeKhdKDpzBxPjI36" options:0];
    NSData *expectedSecretKey = [[NSData alloc] initWithBase64EncodedString:@"Cm550dHeqo5I/dVC/bXD9s5Cx8vnyhV/gm7KO5UuviE=" options:0];
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];

    XCTAssertEqualObjects(keyPair.publicKey, expectedPublicKey);
    XCTAssertEqualObjects(keyPair.secretKey, expectedSecretKey);
}

- (void)testGenerateKeyPairWithoutSeed {
    NSData *seed = NULL;
    NSError *error = nil;
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    XCTAssertEqual(keyPair.publicKey.length, 96);
    XCTAssertEqual(keyPair.secretKey.length, 32);
}
@end
