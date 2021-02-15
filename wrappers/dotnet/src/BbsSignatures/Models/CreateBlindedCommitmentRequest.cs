using System;

namespace BbsSignatures
{
    /// <summary>
    /// A request to create a BBS signature that features blinded/committed messages
    /// </summary>
    public class CreateBlindedCommitmentRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateBlindedCommitmentRequest"/> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="messages">The messages.</param>
        /// <param name="nonce">The nonce.</param>
        /// <exception cref="ArgumentNullException">
        /// publicKey
        /// or
        /// messages
        /// or
        /// nonce
        /// </exception>
        public CreateBlindedCommitmentRequest(BbsKey publicKey, IndexedMessage[] messages, byte[] nonce)
        {
            Key = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        /// <summary>
        /// The public key
        /// </summary>
        public BbsKey Key { get; set; }

        /// <summary>
        /// The known messages to sign
        /// </summary>
        public IndexedMessage[] Messages { get; set; }

        /// <summary>
        /// A nonce for the resulting proof
        /// </summary>
        public byte[] Nonce { get; set; }
    }
}