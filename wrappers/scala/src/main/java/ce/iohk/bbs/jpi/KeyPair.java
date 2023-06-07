package ce.iohk.bbs.jpi;

public class KeyPair {
    private final byte[] publicKey;
    private final byte[] privateKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public byte[] getPrivateKey() {
        return privateKey;
    }

}
