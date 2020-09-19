using System;
namespace Hyperledger.Ursa.BbsSignatures
{
    public class VerifyProofRequest
    {
        public VerifyProofRequest(BbsKey publicKey, byte[] proof, IndexedMessage[] messages, string nonce)
        {
            Proof = proof ?? throw new ArgumentNullException(nameof(proof));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        public byte[] Proof { get; set; }

        public IndexedMessage[] Messages { get; set; }

        public string Nonce { get; set; }

        public BbsKey PublicKey { get; set; }
    }
}
