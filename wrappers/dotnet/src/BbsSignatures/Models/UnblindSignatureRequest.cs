using System;
namespace BbsSignatures
{
    /// <summary>
    /// Unblind Signature Request
    /// </summary>
    public class UnblindSignatureRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UnblindSignatureRequest"/> class.
        /// </summary>
        /// <param name="blindedSignature">The blinded signature.</param>
        /// <param name="blindingFactor">The blinding factor.</param>
        /// <exception cref="ArgumentNullException">
        /// blindedSignature
        /// or
        /// blindingFactor
        /// </exception>
        public UnblindSignatureRequest(byte[] blindedSignature, byte[] blindingFactor)
        {
            BlindedSignature = blindedSignature ?? throw new ArgumentNullException(nameof(blindedSignature));
            BlindingFactor = blindingFactor ?? throw new ArgumentNullException(nameof(blindingFactor));
        }

        /// <summary>
        /// Gets or sets the blinded signature.
        /// </summary>
        /// <value>
        /// The blinded signature.
        /// </value>
        public byte[] BlindedSignature { get; set; }

        /// <summary>
        /// Gets or sets the blinding factor.
        /// </summary>
        /// <value>
        /// The blinding factor.
        /// </value>
        public byte[] BlindingFactor { get; set; }
    }
}
