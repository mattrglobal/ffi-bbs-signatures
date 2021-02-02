#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_key_pair.h"
#import "../bbs-signatures/bls12381g2_key_pair.h"
#import "../bbs-signatures/bbs_signature.h"
#import "../bbs-signatures/bbs.h"

@interface BbsSignatureTests : XCTestCase

@end

@implementation BbsSignatureTests

- (void)testSignSingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:1
                                                                 withError:&error];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:bbsKeyPair
                                                messages:messages
                                               withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
}

- (void)testSignMultipleMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:3
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:bbsKeyPair
                                                messages:messages
                                               withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
}

- (void)testSignMultipleMessagesWhenPublicKeySupportsMore {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:5
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:bbsKeyPair
                                                messages:messages
                                               withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
}

- (void)testThrowErrorWhenSigningTooManyMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:1
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];

    [[BbsSignature alloc] sign:bbsKeyPair
                      messages:messages
                     withError:&error];
    
    XCTAssertNotNil(error);
}

- (void)testBlsSignSingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] blsSign:keyPair
                                                   messages:messages
                                                  withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
}

- (void)testBlsSignMultipleMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] blsSign:keyPair
                                                   messages:messages
                                                  withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
}

- (void)testSignAndVerifySingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:1
                                                                 withError:&error];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:bbsKeyPair
                                                messages:messages
                                               withError:&error];
        
    bool isVerified = [signature verify:bbsKeyPair
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertTrue(isVerified);
}

- (void)testSignAndVerifyMultipleMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:3
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] sign:bbsKeyPair
                                                messages:messages
                                               withError:&error];
    
    bool isVerified = [signature verify:bbsKeyPair
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertTrue(isVerified);
}

- (void)testSignThrowErrorWithWrongSingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"kTV8dar9xLWQZ5EzaWYqTRmgA6dw6wcrUw5c///crRD2QQPXX9Di+lgCPCXAA5D8Pytuh6bNSx6k4NZTR9KfSNdaejKl2zTU9poRfzZ2SIskdgSHTZ2y7jLm/UEGKsAs3tticBVj1Pm2GNhQI/OlXQ==" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:1
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature verify:bbsKeyPair
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}

- (void)testSignThrowErrorWithWrongMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ==" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed                                                                                                                       withError:&error]
                                                              messageCount:3
                                                                 withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature verify:bbsKeyPair
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}

- (void)testSignThrowErrorWhenMessagesEmpty {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ==" options:0];
    BbsKeyPair *bbsKeyPair = [[BbsKeyPair alloc] initWithBls12381G2KeyPair:[[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                                                                         withError:&error]
                                                              messageCount:3
                                                                 withError:&error];
    
    NSArray *messages = [NSArray array];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature verify:bbsKeyPair
                               messages:messages
                              withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}

- (void)testBlsSignAndVerifySingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] blsSign:keyPair
                                                   messages:messages
                                                  withError:&error];
    
    bool isVerified = [signature blsVerify:keyPair
                                  messages:messages
                                 withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertTrue(isVerified);
}

- (void)testBlsSignAndVerifyMultipleMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] blsSign:keyPair
                                                   messages:messages
                                                  withError:&error];
    
    bool isVerified = [signature blsVerify:keyPair
                                  messages:messages
                                 withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertTrue(isVerified);
}

- (void)testBlsVerifyThrowErrorWithWrongSingleMessage {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"kTV8dar9xLWQZ5EzaWYqTRmgA6dw6wcrUw5c///crRD2QQPXX9Di+lgCPCXAA5D8Pytuh6bNSx6k4NZTR9KfSNdaejKl2zTU9poRfzZ2SIskdgSHTZ2y7jLm/UEGKsAs3tticBVj1Pm2GNhQI/OlXQ==" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature blsVerify:keyPair
                                  messages:messages
                                 withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}

- (void)testBlsVerifyThrowErrorWithWrongMessages {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData alloc] initWithBase64EncodedString:@"jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ==" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXc==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"xaPXXhFBIbxeIU==" options:0],
                                                  [[NSData alloc] initWithBase64EncodedString:@"BapXXhfBIbxeIU==" options:0], nil];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature blsVerify:keyPair
                                  messages:messages
                                 withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}

- (void)testBlsVerifyThrowErrorWhenMessagesEmpty {
    NSError *error = nil;
    NSData *seed = [[NSData alloc] initWithBase64EncodedString:@"H297BpoOgkfpXcxr1fJyQRiNx1+ZekeQ+OU/AYV/lVxaPXXhFBIbxeIU8kIAAX68cwQ=" options:0];
    NSData *signatureBuffer = [[NSData data] initWithBase64EncodedString:@"jYidhsdqxvAyNXMV4/vNfGM/4AULfSyfvQiwh+dDd4JtnT5xHnwpzMYdLdHzBYwXaGE1k6ln/pwtI4RwQZpl03SCv/mT/3AdK8PB2y43MGdMSeGTyZGfZf+rUrEDEs3lTfmPK54E+JBzd96gnrF2iQ==" options:0];
    
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithSeed:seed
                                                               withError:&error];
    
    NSArray *messages = [NSArray array];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureBuffer
                                                        withError:&error];
    
    bool isVerified = [signature blsVerify:keyPair
                                  messages:messages
                                 withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    XCTAssertFalse(isVerified);
}
@end
