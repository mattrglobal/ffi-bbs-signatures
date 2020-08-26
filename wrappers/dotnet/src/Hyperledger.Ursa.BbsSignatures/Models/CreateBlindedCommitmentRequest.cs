using System;

namespace Hyperledger.Ursa.BbsSignatures
{
    /// <summary>
    /// A request to create a BBS signature that features blinded/committed messages
    /// </summary>
    public class CreateBlindedCommitmentRequest
    {
        public CreateBlindedCommitmentRequest(BbsKeyPair publicKey, IndexedMessage[] messages, string nonce)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        /// <summary>
        /// The public key
        /// </summary>
        public BbsKeyPair PublicKey { get; set; }

        /// <summary>
        /// The known messages to sign
        /// </summary>
        public IndexedMessage[] Messages { get; set; }

        /// <summary>
        /// A nonce for the resulting proof
        /// </summary>
        public string Nonce { get; set; }
    }
}