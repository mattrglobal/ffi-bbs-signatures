using System;

namespace BbsSignatures
{
    /// <summary>
    /// Verify Blinded Commitment Request
    /// </summary>
    public class VerifyBlindedCommitmentRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="VerifyBlindedCommitmentRequest"/> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="proof">The proof.</param>
        /// <param name="blindedIndices">The blinded indices.</param>
        /// <param name="nonce">The nonce.</param>
        /// <exception cref="ArgumentNullException">
        /// publicKey
        /// or
        /// proof
        /// or
        /// blindedIndices
        /// or
        /// nonce
        /// </exception>
        public VerifyBlindedCommitmentRequest(BbsKey publicKey, byte[] proof, uint[] blindedIndices, byte[] nonce)
        {
            Key = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Proof = proof ?? throw new ArgumentNullException(nameof(proof));
            BlindedIndices = blindedIndices ?? throw new ArgumentNullException(nameof(blindedIndices));
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));
        }

        /// <summary>
        /// Gets or sets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public BbsKey Key { get; set; }

        /// <summary>
        /// Gets or sets the proof.
        /// </summary>
        /// <value>
        /// The proof.
        /// </value>
        public byte[] Proof { get; set; }

        /// <summary>
        /// Gets or sets the blinded indices.
        /// </summary>
        /// <value>
        /// The blinded indices.
        /// </value>
        public uint[] BlindedIndices { get; set; }

        /// <summary>
        /// Gets or sets the nonce.
        /// </summary>
        /// <value>
        /// The nonce.
        /// </value>
        public byte[] Nonce { get; set; }
    }
}