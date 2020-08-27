using System;

namespace Hyperledger.Ursa.BbsSignatures
{
    public class VerifyBlindedCommitmentRequest
    {
        public VerifyBlindedCommitmentRequest(BbsKeyPair publicKey, byte[] proof, uint[] blindedIndices, string nonce)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Proof = proof ?? throw new ArgumentNullException(nameof(proof));
            BlindedIndices = blindedIndices ?? throw new ArgumentNullException(nameof(blindedIndices));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        public BbsKeyPair PublicKey { get; set; }

        public byte[] Proof { get; set; }

        public uint[] BlindedIndices { get; set; }

        public string Nonce { get; set; }
    }
}