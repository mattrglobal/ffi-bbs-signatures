package bbs.signatures;

public class BlindCommitmentContext {
    public byte[] commitment;
    public byte[] proof;
    public byte[] blinding_factor;

    public BlindCommitmentContext(byte[] commitment, byte[] proof, byte[] blinding_factor) {
        this.commitment = commitment;
        this.proof = proof;
        this.blinding_factor = blinding_factor;
    }
}
