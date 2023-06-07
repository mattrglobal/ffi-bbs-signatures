package ce.iohk.bbs.jpi;

import ce.iohk.bbs.BbsPlusOps;
import ce.iohk.bbs.MessageWithProofType;

import java.util.List;

public interface BbsJpi {

    KeyPair createKeyPair();
    byte[] createBbsPublicKey(byte[] blsPublicKey,
                                    int numMessages);
    boolean verify(byte[][] messages, byte[] signature, byte[] publicKey);

    byte[] sign(byte[][] messages, KeyPair keyPair);

    BbsPlusOps.BlindCommitment createLinkSecretsCommitment(
            byte[] publicKey,
            byte[] nonce,
            byte[][] messages);

    BbsPlusOps.BlindCommitment createLinkSecretCommitment(
            byte[] publicKey,
            byte[] nonce,
            byte[] message);

    boolean verifyBlindCommitment(byte[] publicKey,
                                  byte[] nonce,
                                  byte[] commitmentProof);

    boolean verifyBlindCommitments(byte[] publicKey,
                                   byte[] nonce,
                                   List<Integer> commitmentIndices,
                                   byte[] commitmentProof);

    byte[] blindSign(
            byte[] publicKey,
            byte[] privateKey,
            byte[] blindCommitment,
            List<byte[]> messages,
            int startingIndex);

    byte[] createProof(byte[] blindSig,
                       byte[] nonce,
                       byte[] publicKey,
                       byte[] blindingFactor,
                    List<MessageWithProofType> messages);

    boolean verifyProof(byte[] proof,
                        byte[] publicKey,
                        byte[] nonce,
                        List<byte[]> messages);
}