namespace BbsSignatures
{
    public enum SignatureProofStatus
    {
        /// <summary>
        /// The proof is verified
        /// </summary>
        Success = 200,
        /// <summary>
        /// The proof failed because the signature proof of knowledge failed
        /// </summary>
        BadSignature = 400,
        /// <summary>
        /// The proof failed because a hidden message was invalid when the proof was created
        /// </summary>
        BadHiddenMessage = 401,
        /// <summary>
        /// The proof failed because a revealed message was invalid
        /// </summary>
        BadRevealedMessage = 402,
    }
}
