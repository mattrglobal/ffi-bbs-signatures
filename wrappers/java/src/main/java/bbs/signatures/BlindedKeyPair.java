package bbs.signatures;

public class BlindedKeyPair {
    public byte[] secretKey;
    public byte[] publicKey;
    public byte[] blindingFactor;

    public BlindedKeyPair(byte[] publicKey, byte[] secretKey, byte[] blindingFactor) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
        this.blindingFactor = blindingFactor;
    }
}
