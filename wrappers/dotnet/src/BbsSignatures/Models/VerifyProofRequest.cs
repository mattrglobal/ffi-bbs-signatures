using System;
namespace BbsSignatures
{
    /// <summary>
    /// Verify Proof Request
    /// </summary>
    public class VerifyProofRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VerifyProofRequest"/> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="proof">The proof.</param>
        /// <param name="messages">The messages.</param>
        /// <param name="nonce">The nonce.</param>
        /// <exception cref="ArgumentNullException">
        /// proof
        /// or
        /// messages
        /// or
        /// nonce
        /// or
        /// publicKey
        /// </exception>
        public VerifyProofRequest(BbsKey publicKey, byte[] proof, string[] messages, string nonce)
        {
            Proof = proof ?? throw new ArgumentNullException(nameof(proof));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
            Key = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        }

        /// <summary>
        /// Gets or sets the proof.
        /// </summary>
        /// <value>
        /// The proof.
        /// </value>
        public byte[] Proof { get; set; }

        /// <summary>
        /// Gets or sets the messages.
        /// </summary>
        /// <value>
        /// The messages.
        /// </value>
        public string[] Messages { get; set; }

        /// <summary>
        /// Gets or sets the nonce.
        /// </summary>
        /// <value>
        /// The nonce.
        /// </value>
        public string Nonce { get; set; }

        /// <summary>
        /// Gets or sets the BBS+ key.
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        public BbsKey Key { get; set; }
    }
}
