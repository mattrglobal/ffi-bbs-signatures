package bbs.signatures;

import org.junit.Test;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

import static org.junit.Assert.*;

public class BbsSignatureTest {

    public KeyPair keyPair;

    private KeyPair getBls12381G2KeyPair() {
        byte[] seed = new byte[0];
        KeyPair keyPair = null;

        try {
            keyPair = Bbs.generateBls12381G2Key(seed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(keyPair);
        return keyPair;
    }

    private ProofMessage[] byteArrayToProofMessage(byte[][] messages, int type) {
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[messages.length];

        for (int i = 0; i < messages.length; i++) {
            proofMessage[i] = new ProofMessage(type, messages[i], blindingFactor);
        }

        return proofMessage;
    }

    @Test
    public void canGetCorrectBls12381G1PublicKeySize() {
        int size = Bbs.getBls12381G1PublicKeySize();
        assertEquals(48, size);
    }

    @Test
    public void canGetCorrectBls12381G2PublicKeySize() {
        int size = Bbs.getBls12381G2PublicKeySize();
        assertEquals(96, size);
    }

    @Test
    public void canGetSecretKeySize() {
        int size = Bbs.getSecretKeySize();
        assertEquals(32, size);
    }

    @Test
    public void canGetSignatureSize() {
        int size = Bbs.getSignatureSize();
        assertEquals(112, size);
    }

    @Test
    public void canGetBlindSignatureSize() {
        int size = Bbs.getBlindSignatureSize();
        assertEquals(112, size);
    }

    @Test
    public void canGenerateBls12381G1Key() {
        byte[] seed = new byte[0];
        KeyPair keyPair = null;

        try {
            keyPair = Bbs.generateBls12381G1Key(seed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(keyPair);
        assertEquals(Bbs.getBls12381G1PublicKeySize(), keyPair.publicKey.length);
        assertEquals(Bbs.getSecretKeySize(), keyPair.secretKey.length);
    }

    @Test
    public void shouldThrowExceptionMessageWhenFailToGenerateBls12381G1Key() {
        byte[] seed = null;

        try {
            Bbs.generateBls12381G1Key(seed);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to generate keys", exception.getMessage());
        }
    }

    @Test
    public void canGenerateBls12381G2Key() {
        byte[] seed = new byte[0];
        KeyPair keyPair = null;

        try {
            keyPair = Bbs.generateBls12381G2Key(seed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(keyPair);
        assertEquals(Bbs.getBls12381G2PublicKeySize(), keyPair.publicKey.length);
        assertEquals(Bbs.getSecretKeySize(), keyPair.secretKey.length);
    }

    @Test
    public void shouldThrowExceptionMessageWhenFailToGenerateBls12381G2Key() {
        byte[] seed = null;

        try {
            Bbs.generateBls12381G2Key(seed);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to generate keys", exception.getMessage());
        }
    }

    @Test
    public void canSignMessage() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[][] messages = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.length);
        byte[] secretKey = keyPair.secretKey;

        byte[] signature = new byte[Bbs.getSignatureSize()];

        try {
            signature = Bbs.sign(secretKey, bbsKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);
    }

    @Test
    public void canBlsSignMessage() {
        KeyPair keyPair = getBls12381G2KeyPair();
        byte[] publicKey = keyPair.publicKey;
        byte[] secretKey = keyPair.secretKey;

        byte[][] messages = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };

        byte[] signature = new byte[Bbs.getSignatureSize()];

        try {
            signature = Bbs.blsSign(secretKey, publicKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);
    }

    @Test
    public void canVerifyMessage() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[][] messages = {"message1".getBytes()};
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.length);
        byte[] secretKey = keyPair.secretKey;

        byte[] signature = new byte[Bbs.getSignatureSize()];

        try {
            signature = Bbs.sign(secretKey, bbsKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = Bbs.verify(bbsKey, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void canBlsVerifyMessage() {
        KeyPair keyPair = getBls12381G2KeyPair();
        byte[] publicKey = keyPair.publicKey;
        byte[] secretKey = keyPair.secretKey;
        byte[][] messages = {"message1".getBytes()};

        byte[] signature = new byte[Bbs.getSignatureSize()];

        try {
            signature = Bbs.blsSign(secretKey, publicKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = Bbs.blsVerify(publicKey, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerificationPublicKeyIsInvalid() {
        byte[] invalidPublicKey = new byte[96];
        byte[][] messages = {"message1".getBytes()};
        byte[] signature = new byte[112];

        try {
            Bbs.verify(invalidPublicKey, signature, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set public key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerificationSignatureIsInvalid() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[][] messages = {"message1".getBytes()};
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.length);
        byte[] invalidSignature = new byte[112];

        try {
            Bbs.verify(bbsKey, invalidSignature, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set signature", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenUnableToVerifySignature() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[][] messages = {"message1".getBytes()};
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.length);
        byte[] secretKey = keyPair.secretKey;
        byte[] signature = new byte[112];

        try {
            signature = Bbs.sign(secretKey, bbsKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        try {
            Bbs.verify(bbsKey, new byte[112], messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set signature", exception.getMessage());
        }
    }

    @Test
    public void canCreateBlindCommitment() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[] message = "message1".getBytes();
        Map<Integer, byte[]> messages = new HashMap<Integer, byte[]>() {{
            put(0, message);
        }};

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.size());
        byte[] nonce = new byte[32];

        BlindCommitmentContext context = null;

        try {
            context = Bbs.blindCommitment(bbsKey, messages, nonce);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(context);
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindCommitmentPublicKeyIsInvalid() {
        byte[] invalidPublicKey = new byte[96];
        byte[] nonce = new byte[32];
        Map<Integer, byte[]> messages = Collections.emptyMap();

        try {
            Bbs.blindCommitment(invalidPublicKey, messages, nonce);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set public key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindCommitmentNonceIsInvalid() {
        KeyPair keyPair = getBls12381G2KeyPair();

        Map<Integer, byte[]> messages = Collections.emptyMap();
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, 1);
        byte[] invalidNonce = null;

        try {
            Bbs.blindCommitment(bbsKey, messages, invalidNonce);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set nonce", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindCommitmentMessageIsInvalid() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[] invalidMessage = "".getBytes();
        Map<Integer, byte[]> invalidMessages = new HashMap<Integer, byte[]>() {{
            put(0, invalidMessage);
        }};

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, invalidMessages.size());
        byte[] nonce = new byte[32];

        try {
            Bbs.blindCommitment(bbsKey, invalidMessages, nonce);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to add message", exception.getMessage());
        }
    }

    @Test
    public void canBlindSign() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[] message = "message1".getBytes();
        Map<Integer, byte[]> messages = new HashMap<Integer, byte[]>() {{
            put(0, message);
        }};

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.size());
        byte[] secretKey = new byte[32];
        byte[] nonce = new byte[32];

        BlindCommitmentContext blindCommitmentContext = null;

        try {
            blindCommitmentContext = Bbs.blindCommitment(bbsKey, messages, nonce);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(blindCommitmentContext);

        byte[] blindSignature = new byte[112];

        try {
            blindSignature = Bbs.blindSign(secretKey, bbsKey, blindCommitmentContext.commitment, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(blindSignature);
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindSignSecretKeyIsInvalid() {
        byte[] publicKey = new byte[96];
        byte[] invalidSecretKey = null;
        byte[] commitment = new byte[48];
        Map<Integer, byte[]> messages = Collections.emptyMap();

        try {
            Bbs.blindSign(invalidSecretKey, publicKey, commitment, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set secret key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindSignPublicKeyIsInvalid() {
        byte[] publicKey = new byte[96];
        byte[] secretKey = new byte[32];
        byte[] commitment = new byte[48];
        Map<Integer, byte[]> messages = Collections.emptyMap();

        try {
            Bbs.blindSign(secretKey, publicKey, commitment, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set public key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindSignCommitmentIsInvalid() {
        KeyPair keyPair = getBls12381G2KeyPair();

        Map<Integer, byte[]> messages = Collections.emptyMap();
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, 1);
        byte[] secretKey = new byte[32];
        byte[] invalidCommitment = new byte[48];

        try {
            Bbs.blindSign(secretKey, bbsKey, invalidCommitment, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set commitment", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenBlindSignMessageIsInvalid() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[] message = "message1".getBytes();
        Map<Integer, byte[]> messages = new HashMap<Integer, byte[]>() {{
            put(0, message);
        }};
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.size());
        byte[] secretKey = new byte[32];
        byte[] nonce = new byte[32];

        BlindCommitmentContext blindCommitmentContext = null;

        try {
            blindCommitmentContext = Bbs.blindCommitment(bbsKey, messages, nonce);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(blindCommitmentContext);

        Map<Integer, byte[]> invalidMessages = new HashMap<Integer, byte[]>() {{
            put(0, "".getBytes());
        }};

        try {
            Bbs.blindSign(secretKey, bbsKey, blindCommitmentContext.commitment, invalidMessages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to add message", exception.getMessage());
        }
    }

    @Test
    public void canUnblindSignature() {
        byte[] blindSignature = new byte[112];
        byte[] blindingFactor = new byte[32];
        byte[] signature;

        signature = Bbs.unblindSignature(blindSignature, blindingFactor);
        assertNotNull(signature);
    }

    @Test
    public void shouldReturnNullWhenCantUnblindSignature() {
        byte[] blindSignature = null;
        byte[] blindingFactor = null;
        byte[] signature;

        signature = Bbs.unblindSignature(blindSignature, blindingFactor);
        assertNull("The signature is null", signature);
    }

    @Test
    public void testCreateProofRevealingSingleMessageFromSingleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        int type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(type, message, blindingFactor),
        };

        byte[] proof = new byte[0];
        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);

        try {
            proof = Bbs.createProof(bbsKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);
    }

    @Test
    public void testBlsCreateProofRevealingSingleMessageFromSingleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        int type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(type, message, blindingFactor),
        };

        byte[] proof = new byte[0];

        try {
            proof = Bbs.blsCreateProof(publicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);
    }

    @Test
    public void shouldThrowExceptionMessageWhenProofPublicKeyIsInvalid() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        int type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(type, message, blindingFactor),
        };

        byte[] invalidPublicKey = new byte[0];

        try {
            Bbs.createProof(invalidPublicKey, nonce, signature, proofMessage);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set public key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenProofNonceIsInvalid() {
        byte[] invalidNonce = null;
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        int type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(type, message, blindingFactor),
        };

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);

        try {
            Bbs.createProof(bbsKey, invalidNonce, signature, proofMessage);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set nonce", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenProofSignatureIsInvalid() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] invalidSignature = Base64.getDecoder().decode("rpldJh9DkYe4FvX7WPYI+GNhBM7uB3UGg3NcJX+NTts9E5R9TtHSYszqVfLxdq0Mb45jyd82laouneFYjB5TreM5Qpo9TyO0yNPdaanmfW0wCeLp3r0bhdfOF67GGL01KHY56ojoaSWBmr2lpqRU2Q==");

        int type = ProofMessage.PROOF_MESSAGE_TYPE_REVEALED;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(type, message, blindingFactor),
        };

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);

        try {
            Bbs.createProof(bbsKey, nonce, invalidSignature, proofMessage);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to create proof", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenProofMessageIsInvalid() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        int invalidType = 5;
        byte[] blindingFactor = new byte[0];
        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(invalidType, message, blindingFactor),
        };

        byte[] bbsKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);

        try {
            Bbs.createProof(bbsKey, nonce, signature, proofMessage);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to add proof message", exception.getMessage());
        }
    }

    @Test
    public void testVerifyProofRevealingSingleMessageFromSingleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, message, new byte[0]),
        };

        byte[] proof = new byte[0];
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);

        try {
            proof = Bbs.createProof(bbsPublicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        byte[][] messages = {
                message
        };

        boolean isVerified = false;

        try {
            isVerified = Bbs.verifyProof(bbsPublicKey, proof, nonce, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void testBlsVerifyProofRevealingSingleMessageFromSingleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] signature = Base64.getDecoder().decode("r00WeXEj+07DUZb3JY6fbbKhHtQcxtLZsJUVU6liFZQKCLQYu77EXFZx4Vaa5VBtKpPK6tDGovHGgrgyizOm70VUZgzzBb0emvRIGSWhAKkcLL1z1HYwApnUE6XFFb96LUF4XM//QhEM774dX4ciqQ==");

        ProofMessage[] proofMessage = new ProofMessage[]{
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, message, new byte[0]),
        };

        byte[] proof = new byte[0];

        try {
            proof = Bbs.blsCreateProof(publicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        byte[][] messages = {
                message
        };

        boolean isVerified = false;

        try {
            isVerified = Bbs.blsVerifyProof(publicKey, proof, nonce, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerifyProofPublicKeyIsInvalid() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] proof = Base64.getDecoder().decode("AAEBoaFg6VxcB6O4VIKYJO0+HzKeanbXM4uwmCHLNBm3lwdeBkfpqJ6WoVTy9J0vsvtIubBEnwEv9y1azjWWQx2kawyVzN2dvUNRK9IRLQC2ut9Iz8o3Roh4KNsG1Woe1NZKltxlXl2Be0AaoA0/8c0kyssv97BEFpKRH/hrp8UqQas3X/FyUeqQ6d7yJjMnGvIdAAAAdIvOcT/XUeKc0EeUnLVvrvpbnUAtRjWduhwPWFlDVT00Wo4LwMw/lxIDvF+TNecX3QAAAAIESbWq6giuMgFEi8bxkcrmWCoS3PsEpRkfinUw0Q8azAZhg1x/B56PbJGDGmb6jRNNaCB7DPrMNM2vUcEY07yHiY8Ro37TEL8B2M6Bh8oSYZriOXDKys+yHokCQ28YV/dj1J1vNJYScfBSZpyCKOn7AAAAAklvabUJvsh4FfKc0k/gO2VbUZwf4/4qGWnF49Ck/6SJJlzMtn5ZHzjPFNPhOsua8NtHVeni1cGrRHaLTfoEGio=");
        byte[] bbsPublicKey = "invalidPublicKey".getBytes();

        byte[][] messages = {
                message
        };

        try {
            Bbs.verifyProof(bbsPublicKey, proof, nonce, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set public key", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerifyProofUnableToSetProof() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);
        byte[] invalidProof = "".getBytes();

        byte[][] messages = {
                message
        };

        try {
            Bbs.verifyProof(bbsPublicKey, invalidProof, nonce, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set proof", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerifyProofUnableToSetNonce() {
        byte[] invalidNonce = null;
        byte[] message = Base64.getDecoder().decode("dXpBb1FGcUxnUmVpZHc9PQ==");
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);
        byte[] proof = Base64.getDecoder().decode("AAEBoaFg6VxcB6O4VIKYJO0+HzKeanbXM4uwmCHLNBm3lwdeBkfpqJ6WoVTy9J0vsvtIubBEnwEv9y1azjWWQx2kawyVzN2dvUNRK9IRLQC2ut9Iz8o3Roh4KNsG1Woe1NZKltxlXl2Be0AaoA0/8c0kyssv97BEFpKRH/hrp8UqQas3X/FyUeqQ6d7yJjMnGvIdAAAAdIvOcT/XUeKc0EeUnLVvrvpbnUAtRjWduhwPWFlDVT00Wo4LwMw/lxIDvF+TNecX3QAAAAIESbWq6giuMgFEi8bxkcrmWCoS3PsEpRkfinUw0Q8azAZhg1x/B56PbJGDGmb6jRNNaCB7DPrMNM2vUcEY07yHiY8Ro37TEL8B2M6Bh8oSYZriOXDKys+yHokCQ28YV/dj1J1vNJYScfBSZpyCKOn7AAAAAklvabUJvsh4FfKc0k/gO2VbUZwf4/4qGWnF49Ck/6SJJlzMtn5ZHzjPFNPhOsua8NtHVeni1cGrRHaLTfoEGio=");

        byte[][] messages = {
                message
        };

        try {
            Bbs.verifyProof(bbsPublicKey, proof, invalidNonce, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to set nonce", exception.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionMessageWhenVerifyProofUnableToAddMessage() {
        byte[] nonce = Base64.getDecoder().decode("MDEyMzQ1Njc4OQ==");
        byte[] invalidMessage = "".getBytes();
        byte[] publicKey = Base64.getDecoder().decode("qJgttTOthlZHltz+c0PE07hx3worb/cy7QY5iwRegQ9BfwvGahdqCO9Q9xuOnF5nD/Tq6t8zm9z26EAFCiaEJnL5b50D1cHDgNxBUPEEae+4bUb3JRsHaxBdZWDOo3pb");
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 1);
        byte[] proof = Base64.getDecoder().decode("AAEBoaFg6VxcB6O4VIKYJO0+HzKeanbXM4uwmCHLNBm3lwdeBkfpqJ6WoVTy9J0vsvtIubBEnwEv9y1azjWWQx2kawyVzN2dvUNRK9IRLQC2ut9Iz8o3Roh4KNsG1Woe1NZKltxlXl2Be0AaoA0/8c0kyssv97BEFpKRH/hrp8UqQas3X/FyUeqQ6d7yJjMnGvIdAAAAdIvOcT/XUeKc0EeUnLVvrvpbnUAtRjWduhwPWFlDVT00Wo4LwMw/lxIDvF+TNecX3QAAAAIESbWq6giuMgFEi8bxkcrmWCoS3PsEpRkfinUw0Q8azAZhg1x/B56PbJGDGmb6jRNNaCB7DPrMNM2vUcEY07yHiY8Ro37TEL8B2M6Bh8oSYZriOXDKys+yHokCQ28YV/dj1J1vNJYScfBSZpyCKOn7AAAAAklvabUJvsh4FfKc0k/gO2VbUZwf4/4qGWnF49Ck/6SJJlzMtn5ZHzjPFNPhOsua8NtHVeni1cGrRHaLTfoEGio=");

        byte[][] messages = {
                invalidMessage
        };

        try {
            Bbs.verifyProof(bbsPublicKey, proof, nonce, messages);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to add message", exception.getMessage());
        }
    }

    @Test
    public void testBlsVerifyProofRevealingSingleMessageFromMultipleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("4mmd5EVmGd0POg+/4M2l0A==");
        byte[][] messages = {
                Base64.getDecoder().decode("oHMsObG6rdeVlAa5bWIwRA=="),
                Base64.getDecoder().decode("DdJ54KFvrIJEiDTx8oV62g=="),
                Base64.getDecoder().decode("k13FuVng4HlzyLU1zHACoA=="),
        };
        byte[] publicKey = Base64.getDecoder().decode("pnHwdXyl9R2erFrtJd1r5OAXioXFigeBrb94ir7Vzs8S38hW/N1y+BddYIunhXREApDDC75Z24ulyUZHo5wc09ZQE+hjdIUxsJCJZq9BTMOiMljq+V8Op9v7CVWmSzop");
        byte[] signature = Base64.getDecoder().decode("gwoVS/AOXDQJJwBhXfioEIo9dW//ppDJx/2TwaO6f6ATp3c8TH6I1NL8URh7X2bPJaeEKE0fMBS/uZeiQwbr92rTjw8BfNoxNDHrBZEnEmJbWC9fLyKfl3pcBNbvT2ESEKioGgHnwPiWuQ6WfBV7pg==");

        ProofMessage[] proofMessage = {
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[0], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING, messages[1], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING, messages[2], new byte[0]),
        };

        byte[] proof = new byte[0];
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 3);

        try {
            proof = Bbs.createProof(bbsPublicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        byte[][] revealed = {
                messages[0]
        };

        boolean isVerified = false;

        try {
            isVerified = Bbs.verifyProof(bbsPublicKey, proof, nonce, revealed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void testBlsVerifyProofRevealingMultipleMessagesFromMultipleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("4mmd5EVmGd0POg+/4M2l0A==");
        byte[][] messages = {
                Base64.getDecoder().decode("oHMsObG6rdeVlAa5bWIwRA=="),
                Base64.getDecoder().decode("DdJ54KFvrIJEiDTx8oV62g=="),
                Base64.getDecoder().decode("k13FuVng4HlzyLU1zHACoA=="),
        };
        byte[] publicKey = Base64.getDecoder().decode("pnHwdXyl9R2erFrtJd1r5OAXioXFigeBrb94ir7Vzs8S38hW/N1y+BddYIunhXREApDDC75Z24ulyUZHo5wc09ZQE+hjdIUxsJCJZq9BTMOiMljq+V8Op9v7CVWmSzop");
        byte[] signature = Base64.getDecoder().decode("gwoVS/AOXDQJJwBhXfioEIo9dW//ppDJx/2TwaO6f6ATp3c8TH6I1NL8URh7X2bPJaeEKE0fMBS/uZeiQwbr92rTjw8BfNoxNDHrBZEnEmJbWC9fLyKfl3pcBNbvT2ESEKioGgHnwPiWuQ6WfBV7pg==");

        ProofMessage[] proofMessage = {
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[0], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING, messages[1], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[2], new byte[0]),
        };

        byte[] proof = new byte[0];
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 3);

        try {
            proof = Bbs.createProof(bbsPublicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        byte[][] revealed = {
                messages[0],
                messages[2]
        };

        boolean isVerified = false;

        try {
            isVerified = Bbs.verifyProof(bbsPublicKey, proof, nonce, revealed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void testBlsVerifyProofRevealingAllMessagesFromMultipleMessageSignature() {
        byte[] nonce = Base64.getDecoder().decode("4mmd5EVmGd0POg+/4M2l0A==");
        byte[][] messages = {
                Base64.getDecoder().decode("oHMsObG6rdeVlAa5bWIwRA=="),
                Base64.getDecoder().decode("DdJ54KFvrIJEiDTx8oV62g=="),
                Base64.getDecoder().decode("k13FuVng4HlzyLU1zHACoA=="),
        };
        byte[] publicKey = Base64.getDecoder().decode("pnHwdXyl9R2erFrtJd1r5OAXioXFigeBrb94ir7Vzs8S38hW/N1y+BddYIunhXREApDDC75Z24ulyUZHo5wc09ZQE+hjdIUxsJCJZq9BTMOiMljq+V8Op9v7CVWmSzop");
        byte[] signature = Base64.getDecoder().decode("gwoVS/AOXDQJJwBhXfioEIo9dW//ppDJx/2TwaO6f6ATp3c8TH6I1NL8URh7X2bPJaeEKE0fMBS/uZeiQwbr92rTjw8BfNoxNDHrBZEnEmJbWC9fLyKfl3pcBNbvT2ESEKioGgHnwPiWuQ6WfBV7pg==");

        ProofMessage[] proofMessage = {
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[0], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[1], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[2], new byte[0]),
        };

        byte[] proof = new byte[0];
        byte[] bbsPublicKey = Bbs.blsPublicToBbsPublicKey(publicKey, 3);

        try {
            proof = Bbs.createProof(bbsPublicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        byte[][] revealed = {
                messages[0],
                messages[1],
                messages[2]
        };

        boolean isVerified = false;

        try {
            isVerified = Bbs.verifyProof(bbsPublicKey, proof, nonce, revealed);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test
    public void testGetTotalMessagesCountForProof() {
        KeyPair keyPair = getBls12381G2KeyPair();

        byte[] nonce = Base64.getDecoder().decode("NoWZhtX+u1wWLtUfPMmku1FtU2I=");
        byte[][] messages = {
                "+FxEv3VLcNZ8sA==".getBytes(),
                "eI2RcRExnbP8hw==".getBytes(),
                "wll4zckqWAb0Kg==".getBytes(),
        };

        byte[] publicKey = Bbs.blsPublicToBbsPublicKey(keyPair.publicKey, messages.length);
        byte[] secretKey = keyPair.secretKey;
        byte[] signature = new byte[Bbs.getSignatureSize()];

        try {
            signature = Bbs.sign(secretKey, publicKey, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        ProofMessage[] proofMessage = {
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_REVEALED, messages[0], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING, messages[1], new byte[0]),
                new ProofMessage(ProofMessage.PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING, messages[2], new byte[0]),
        };

        byte[] proof = new byte[0];

        try {
            proof = Bbs.createProof(publicKey, nonce, signature, proofMessage);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(proof);

        int total_messages = 0;

        try {
            total_messages = Bbs.getTotalMessagesCountForProof(proof);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertEquals(3, total_messages);
    }
}
