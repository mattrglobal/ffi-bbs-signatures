using System;

namespace BbsSignatures
{
    /// <summary>
    /// A request to create a BBS signature that features blinded/commited messages
    /// </summary>
    public class BlindSignRequest
    {
        public BlindSignRequest(BlsKeyPair secretKey, BbsKey publicKey, byte[] commitment, IndexedMessage[] messages)
        {
            KeyPair = secretKey ?? throw new ArgumentNullException(nameof(secretKey));
            Key = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Commitment = commitment ?? throw new ArgumentNullException(nameof(commitment));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
        }

        /// <summary>
        /// The secret key of the signer
        /// </summary>
        public BlsKeyPair KeyPair { get; set; }

        /// <summary>
        /// The public key of the signer
        /// </summary>
        public BbsKey Key { get; set; }

        /// <summary>
        /// The resulting commitment of the blinded messages to sign
        /// </summary>
        public byte[] Commitment { get; set; }

        /// <summary>
        /// The known messages to sign
        /// </summary>
        public IndexedMessage[] Messages { get; set; }
    }
}