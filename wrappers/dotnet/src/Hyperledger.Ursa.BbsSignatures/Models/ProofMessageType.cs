namespace BbsSignatures
{
    /// <summary>
    /// Proof message type
    /// </summary>
    public enum ProofMessageType
    {
        /// <summary>
        /// The revealed
        /// </summary>
        Revealed = 1,
        /// <summary>
        /// The hidden proof specific blinding
        /// </summary>
        HiddenProofSpecificBlinding = 2,
        /// <summary>
        /// The hidden external blinding
        /// </summary>
        HiddenExternalBlinding = 3,
    }
}
