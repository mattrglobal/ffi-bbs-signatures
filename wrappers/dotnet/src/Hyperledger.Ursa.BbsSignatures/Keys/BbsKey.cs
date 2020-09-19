using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Hyperledger.Ursa.BbsSignatures
{
    /// <summary>
    /// A BBS+ key pair
    /// </summary>
    public class BbsKey
    {
        public BbsKey(byte[] publicKey, uint messageCount)
        {
            PublicKey = new ReadOnlyCollection<byte>(publicKey);
            MessageCount = messageCount;
        }

        /// <summary>
        /// Raw public key value for the key pair
        /// </summary>
        /// <returns></returns>
        public ReadOnlyCollection<byte> PublicKey { get; }

        /// <summary>
        /// Number of messages that can be signed
        /// </summary>
        /// <value>
        /// The message count.
        /// </value>
        public uint MessageCount { get; }
    }
}