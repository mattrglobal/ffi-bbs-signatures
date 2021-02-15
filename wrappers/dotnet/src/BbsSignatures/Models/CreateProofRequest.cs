using System;
using System.Linq;

namespace BbsSignatures
{
    /// <summary>
    /// A request to create a BBS proof from a supplied BBS signature
    /// </summary>
    public class CreateProofRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CreateProofRequest"/> class.
        /// </summary>
        /// <param name="publicKey">Public key of the original signer of the signature</param>
        /// <param name="messages">The messages that were originally signed</param>
        /// <param name="signature">BBS signature to generate the BBS proof from</param>
        /// <param name="blindingFactor">The blinding factor used in blinded signature, if any messages are hidden using <see cref="ProofMessageType.HiddenExternalBlinding"/></param>
        /// <param name="nonce">A nonce for the resulting proof</param>
        /// <exception cref="System.ArgumentNullException">
        /// publicKey
        /// or
        /// messages
        /// or
        /// signature
        /// or
        /// nonce
        /// or
        /// Blinding factor must be provided
        /// </exception>
        public CreateProofRequest(BbsKey publicKey, ProofMessage[] messages, byte[] signature, byte[]? blindingFactor, byte[] nonce)
        {
            Key = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            Messages = messages ?? throw new ArgumentNullException(nameof(messages));
            Signature = signature ?? throw new ArgumentNullException(nameof(signature));
            BlindingFactor = blindingFactor;
            Nonce = nonce ?? throw new ArgumentNullException(nameof(nonce));

            if (messages.Any(x => x.ProofType == ProofMessageType.HiddenExternalBlinding) && blindingFactor == null)
            {
                throw new ArgumentNullException("Blinding factor must be provided");
            }
        }

        /// <summary>
        /// Public key of the original signer of the signature
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        public BbsKey Key { get; set; }

        /// <summary>
        /// The messages that were originally signed
        /// </summary>
        /// <value>
        /// The messages.
        /// </value>
        public ProofMessage[] Messages { get; set; }

        /// <summary>
        /// BBS signature to generate the BBS proof from
        /// </summary>
        /// <value>
        /// The signature.
        /// </value>
        public byte[] Signature { get; set; }

        /// <summary>
        /// The blinding factor used in blinded signature, if any messages are hidden using <see cref="ProofMessageType.HiddenExternalBlinding"/>
        /// </summary>
        /// <value>
        /// The blinding factor.
        /// </value>
        public byte[]? BlindingFactor { get; set; }

        /// <summary>
        /// A nonce for the resulting proof
        /// </summary>
        /// <value>
        /// The nonce.
        /// </value>
        public byte[] Nonce { get; set; }
    }
}