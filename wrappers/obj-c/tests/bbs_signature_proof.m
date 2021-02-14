#import <XCTest/XCTest.h>
#import "../bbs-signatures/bbs_key_pair.h"
#import "../bbs-signatures/bls12381g2_key_pair.h"
#import "../bbs-signatures/bbs_signature.h"
#import "../bbs-signatures/bbs_signature_proof.h"

@interface BbsSignatureProofTests : XCTestCase

@end

@implementation BbsSignatureProofTests

- (void)testCreateProofRevealingSingleMessageFromSingleMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"Um10bkRCSkhzbzVpU2c9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pboZyjM38YgjaUBcjftZi5gb58Qz13XeRJpiuUHH06I7/1Eb8oVtIW5SGMNfKaqKhBAAAAAYPPztgxfWWw01/0SSug1oLfVuI4XUqhgyZ3rS6eTkOLjnyR3ObXb0XCD2Mfcxiv6w==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"rpldJh9DkYe4FvX7WPYI+GNhBM7uB3UGg3NcJX+NTts9E5R9TtHSYszqVfLxdq0Mb45jyd82laouneFYjB5TreM5Qpo9TyO0yNPdaanmfW0wCeLp3r0bhdfOF67GGL01KHY56ojoaSWBmr2lpqRU2Q==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    
    XCTAssertEqual(proof.value.length, 383);
}

- (void)testCreateProofRevealingAllMessagesFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:1],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    
    XCTAssertEqual(proof.value.length, 383);
}

- (void)testCreateProofRevealingSingleMessageFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    
    XCTAssertEqual(proof.value.length, 447);
}

- (void)testCreateProofRevealingMultipleMessagesFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    XCTAssertEqual(proof.value.length, 415);
}

- (void)testCreateProofRevealingMultipleMessagesFromMultiMessageSignatureAndVerify {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    XCTAssertEqual(proof.value.length, 415);
    
    bool isVerified = false;
    NSMutableArray *revealedMessages = [NSMutableArray new];
    
    int i = 0;
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        Boolean isRevealed = [revealed containsObject:[[NSNumber alloc] initWithInt:i]];
        
        if(isRevealed) {
            [revealedMessages addObject:message];
        }
        
        i++;
    }
    
    BbsSignatureProof *proofCheck = [[BbsSignatureProof alloc] initWithBytes:proof.value
                                                                   withError:&error];
    
    isVerified = [proofCheck verifyProof:keyPair
                                messages:revealedMessages
                                   nonce:nonce
                               withError:&error];
    
    XCTAssertTrue(isVerified);
}

- (void)testShouldFailVerificationWhenMessageIndicesAreWrong {
    
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"dGk5V1loaEVlajg1anc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pbiZ/pmArLDr3oSCqthKgSZw4VFzzJMFEuHP9AAnOnUJmqkOmvI1ctGLO6kCLFuwQVAAAAA4GrOHdyZEbTWRrTwIdz+KXWcEUHdIx41XSr/RK0TE5+qU7irAhQekOGFpGWQY4rYrDxoHToB4DblaJWUgkSZQLQ5sOfJg3qUJr9MpnDNJ8nNNitL65e6mqnpfsbbT3k94LBQI3/HijeRl29y5dGcLhOxldMtx2SvQg//kWOJ/Ug8e1aVo3V07XkR1Ltx76uzA==" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"qg3PfohWGvbOCZWxcWIZ779aOuNSafjCXLdDux01TTNGm/Uqhr/kZZ1wSmxKwbEWAhctrDCp2mGE0M0l6DlA5R38chMbtnyWMfQgbQpzMQZgPBPUvVWivJyYEysZnQWrAYzZzRPe36VFbFy5ynWx0w==" options:0];
    
    NSError *error = nil;
    BbsKeyPair *keyPair = [[BbsKeyPair alloc] initWithData:publicKey
                                              messageCount:messages.count];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] createProof:signature
                                                              keyPair:keyPair
                                                                nonce:nonce
                                                             messages:messages
                                                             revealed:revealed
                                                            withError:&error];
    XCTAssertEqual(proof.value.length, 415);
    
    bool isVerified = false;
    NSArray *revealedMessages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"SjQyQXhoY2lPVmtFOXc9PQ==" options:0],
                                 [[NSData alloc] initWithBase64EncodedString:@"UE5NbkFSV0lIUCtzMmc9PQ==" options:0], nil];
    
    BbsSignatureProof *proofCheck = [[BbsSignatureProof alloc] initWithBytes:proof.value
                                                                   withError:&error];
    
    isVerified = [proofCheck verifyProof:keyPair
                                messages:revealedMessages
                                   nonce:nonce
                               withError:&error];
    
    XCTAssertFalse(isVerified);
}

- (void)testBlsCreateProofRevealingSingleMessageFromSingleMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"dXpBb1FGcUxnUmVpZHc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData
                                                        withError:&error];
    
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    XCTAssertEqual(proof.value.length, 383);
}

- (void)testBlsCreateProofRevealingAllMessagesFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:1],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"TUdmNzRvZkdkUndOYnc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"uISPYALbiNZwIgu1ndj9onUbkFA9trrhGFQJqJHFOSWCZYAIDUNTysXziar6+MdbPEiJS34OOlKAzxxnxIhFW0lBd4dbLOKf59LZPMRYc91tALAZeriyKcSVa7RzZl50UPjHfs31JrH6RgZ1V9/OVg==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData withError:&error];
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    XCTAssertEqual(proof.value.length, 383);
}

- (void)testBlsCreateProofRevealingSingleMessageFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"TUdmNzRvZkdkUndOYnc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"uISPYALbiNZwIgu1ndj9onUbkFA9trrhGFQJqJHFOSWCZYAIDUNTysXziar6+MdbPEiJS34OOlKAzxxnxIhFW0lBd4dbLOKf59LZPMRYc91tALAZeriyKcSVa7RzZl50UPjHfs31JrH6RgZ1V9/OVg==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData withError:&error];
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    
    XCTAssertEqual(proof.value.length, 447);
}

- (void)testBlsCreateProofRevealingMultipleMessagesFromMultiMessageSignature {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"TUdmNzRvZkdkUndOYnc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"uISPYALbiNZwIgu1ndj9onUbkFA9trrhGFQJqJHFOSWCZYAIDUNTysXziar6+MdbPEiJS34OOlKAzxxnxIhFW0lBd4dbLOKf59LZPMRYc91tALAZeriyKcSVa7RzZl50UPjHfs31JrH6RgZ1V9/OVg==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData withError:&error];
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    
    XCTAssertEqual(proof.value.length, 415);
}

- (void)testBlsCreateProofRevealingMultipleMessagesFromMultiMessageSignatureAndVerify {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"TUdmNzRvZkdkUndOYnc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"uISPYALbiNZwIgu1ndj9onUbkFA9trrhGFQJqJHFOSWCZYAIDUNTysXziar6+MdbPEiJS34OOlKAzxxnxIhFW0lBd4dbLOKf59LZPMRYc91tALAZeriyKcSVa7RzZl50UPjHfs31JrH6RgZ1V9/OVg==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData withError:&error];
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    
    XCTAssertEqual(proof.value.length, 415);
    
    bool isVerified = false;
    NSMutableArray *revealedMessages = [NSMutableArray new];
    
    int i = 0;
    for (NSData *message in messages) {
        bbs_signature_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        Boolean isRevealed = [revealed containsObject:[[NSNumber alloc] initWithInt:i]];
        
        if(isRevealed) {
            [revealedMessages addObject:message];
        }
        
        i++;
    }
    
    BbsSignatureProof *proofCheck = [[BbsSignatureProof alloc] initWithBytes:proof.value
                                                                   withError:&error];
    
    isVerified = [proofCheck blsVerifyProof:keyPair
                                   messages:revealedMessages
                                      nonce:nonce
                                  withError:&error];
    
    XCTAssertTrue(isVerified);
}

- (void)testShouldFailBlsVerificationWhenIndicesAreWrong {
    NSArray *revealed = [NSArray arrayWithObjects:[[NSNumber alloc] initWithInt:0],
                         [[NSNumber alloc] initWithInt:2], nil];
    NSData *nonce = [[NSData alloc] initWithBase64EncodedString:@"MDEyMzQ1Njc4OQ==" options:0];
    NSArray *messages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0],
                         [[NSData alloc] initWithBase64EncodedString:@"TUdmNzRvZkdkUndOYnc9PQ==" options:0], nil];
    NSData *publicKey = [[NSData alloc] initWithBase64EncodedString:@"qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb" options:0];
    NSData *signatureData = [[NSData alloc] initWithBase64EncodedString:@"uISPYALbiNZwIgu1ndj9onUbkFA9trrhGFQJqJHFOSWCZYAIDUNTysXziar6+MdbPEiJS34OOlKAzxxnxIhFW0lBd4dbLOKf59LZPMRYc91tALAZeriyKcSVa7RzZl50UPjHfs31JrH6RgZ1V9/OVg==" options:0];
    
    NSError *error = nil;
    Bls12381G2KeyPair *keyPair = [[Bls12381G2KeyPair alloc] initWithPublicKey:publicKey];
    BbsSignature *signature = [[BbsSignature alloc] initWithBytes:signatureData withError:&error];
    XCTAssertEqual(signature.value.length, 112);
    
    BbsSignatureProof *proof = [[BbsSignatureProof alloc] blsCreateProof:signature
                                                                 keyPair:keyPair
                                                                   nonce:nonce
                                                                messages:messages
                                                                revealed:revealed
                                                               withError:&error];
    
    XCTAssertEqual(proof.value.length, 415);
    
    bool isVerified = false;
    NSArray *revealedMessages = [NSArray arrayWithObjects:[[NSData alloc] initWithBase64EncodedString:@"QytuMXJQejEvdFZ6UGc9PQ==" options:0],
                                 [[NSData alloc] initWithBase64EncodedString:@"aDN4OGNieVNxQzRyTEE9PQ==" options:0], nil];
    
    BbsSignatureProof *proofCheck = [[BbsSignatureProof alloc] initWithBytes:proof.value
                                                                   withError:&error];
    
    isVerified = [proofCheck blsVerifyProof:keyPair
                                   messages:revealedMessages
                                      nonce:nonce
                                  withError:&error];
    
    XCTAssertFalse(isVerified);
}

- (void)testVerifyProofMessagesCount {
    NSData *proofTest = [[NSData alloc] initWithBase64EncodedString:@"AAMBglo7snhzgTYsmyqx2eKN4Ezk7lY6kBjgjAo5KJxg/e9gdpL0khiF6IkIX68CrtJFuKmmQQeH+8J0+WBRbsQx/tEFEN0UryB/sAt0k57WWWrMFvT3SjJsiYOA0/k7PXe8sZsSaz6Ga6o8SJr+lFHv7YzHSMrUBYQEHx+KHebGocvpaqrbUq8O2mV2mM6astgQAAAAdI5L3EocinkRpiD75Ad9aAL/gY0RJsywMrOZpn24vhOB6Mqyn+VRNryfplHOrV9TMwAAAAI1rT3jM6FwUYUG8EsUkjMSTr9rGuheDQ1jTD/TllI9jDLJz3dRSAbRWS/c9MZASSuL37ygtt5lYqrrtQNRdNoHhJnuR5boM0r5wIXypdyTr9WmxGX8DuEpAH8I7HsJqi6FXDVRizCT/sFehDpZLWw6AAAABFyBkQeazRYsRIxD21bumLqykO8u7ilmTAlp0tUvdKGRSFq6YImSMNWoMrbksihesK62+VEdeXBB4QvGA9ZHcQhg1Y60yVDw+XsaZzITZBdOho6KrOMrn4XfAJUWKepiphIgVbyImei/wXTuq8sPkhfi1aUu3EH91yqTtP0COcMN" options:0];
    
    int messagesCount = [[BbsSignatureProof alloc] getMessagesCountFromProof:proofTest];
    XCTAssertEqual(messagesCount, 3);
}

@end
