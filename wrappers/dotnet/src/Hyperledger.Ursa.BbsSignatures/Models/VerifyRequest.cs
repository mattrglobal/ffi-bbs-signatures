using System;

namespace BbsSignatures
{
    /// <summary>
    /// A request to verify a BBS signature for a set of messages
    /// </summary>
    public class VerifyRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VerifyRequest"/> class.
        /// </summary>
        /// <param name="keyPair">The key pair.</param>
        /// <param name="signature">The signature.</param>
        /// <param name="messages">The messages.</param>
        /// <exception cref="ArgumentNullException">
        /// keyPair
        /// or
        /// signature
        /// or
        /// messages
        /// </exception>
        public VerifyRequest(BlsKeyPair keyPair, byte[] signature, string[] messages)
        {
            KeyPair = keyPair ?? throw new ArgumentNullException(nameof(keyPair));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
        }

        /// <summary>
        /// Public key of the signer of the signature
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        public BlsKeyPair KeyPair { get; set; }

        /// <summary>
        /// Raw signature value
        /// </summary>
        /// <value>
        /// The signature.
        /// </value>
        public byte[] Signature { get; set; }

        /// <summary>
        /// Messages that were signed to produce the signature
        /// </summary>
        /// <value>
        /// The messages.
        /// </value>
        public string[] Messages { get; set; }
    }
}