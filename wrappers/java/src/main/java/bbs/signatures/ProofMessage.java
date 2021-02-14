package bbs.signatures;

public class ProofMessage {
    public static final int PROOF_MESSAGE_TYPE_REVEALED = 1;
    public static final int PROOF_MESSAGE_TYPE_HIDDEN_PROOF_SPECIFIC_BLINDING = 2;
    public static final int PROOF_MESSAGE_TYPE_HIDDEN_EXTERNAL_BLINDING = 3;
    public int type;
    public byte[] message;
    public byte[] blinding_factor;

    public ProofMessage(int type, byte[] message, byte[] blinding_factor) {
        this.type = type;
        this.message = message;
        this.blinding_factor = blinding_factor;
    }
}
