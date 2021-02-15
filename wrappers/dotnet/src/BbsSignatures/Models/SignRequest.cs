namespace BbsSignatures
{
    /// <summary>
    /// A request to create a BBS signature for a set of messages from a BLS12-381 key pair
    /// </summary>
    public class SignRequest
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignRequest"/> class.
        /// </summary>
        /// <param name="keyPair">BLS12-381 key pair</param>
        /// <param name="messages">Messages to sign</param>
        public SignRequest(BlsKeyPair keyPair, string[] messages)
        {
            KeyPair = keyPair;
            Messages = messages;
        }

        /// <summary>
        /// BLS12-381 key pair
        /// </summary>
        /// <value>
        /// The key pair.
        /// </value>
        public BlsKeyPair KeyPair { get; set; }

        /// <summary>
        /// Messages to sign
        /// </summary>
        /// <value>
        /// The messages.
        /// </value>
        public string[] Messages { get; set; }
    }
}