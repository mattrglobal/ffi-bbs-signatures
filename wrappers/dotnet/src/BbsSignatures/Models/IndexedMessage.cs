namespace BbsSignatures
{
    /// <summary>
    /// Represents a message and its index within a collection
    /// </summary>
    public struct IndexedMessage
    {
        /// <summary>
        /// The message
        /// </summary>
        public string Message;

        /// <summary>
        /// The message index
        /// </summary>
        public uint Index;


        /// <summary>
        /// Converts to string.
        /// </summary>
        /// <returns>
        /// A <see cref="System.String" /> that represents this instance.
        /// </returns>
        public override string ToString()
        {
            return $"{Index}: {Message}";
        }
    }
}