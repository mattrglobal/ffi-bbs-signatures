using System.Collections.ObjectModel;

namespace Hyperledger.Ursa.BbsSignatures
{
    /// <summary>
    /// A BLS 12-381 key pair
    /// </summary>
    public class BlsKeyPair
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BlsKeyPair" /> class.
        /// </summary>
        /// <param name="secretKey">The secret key.</param>
        /// <param name="deterministicPublicKey">The deterministic public key.</param>
        internal BlsKeyPair(byte[] secretKey, byte[] deterministicPublicKey)
        {
            SecretKey = new ReadOnlyCollection<byte>(secretKey);
            PublicKey = new ReadOnlyCollection<byte>(deterministicPublicKey);
        }

        /// <summary>
        /// Default BLS 12-381 public key length
        /// </summary>
        public int PublicKeySize => NativeMethods.bls_public_key_size();

        /// <summary>
        /// Default BLS 12-381 private key length
        /// </summary>
        public int SecretKeySize => NativeMethods.bls_secret_key_size();

        public BlsKeyPair(byte[] keyData)
        {
            if (keyData.Length == SecretKeySize)
            {
                SecretKey = new ReadOnlyCollection<byte>(keyData);

                using var context = new UnmanagedMemoryContext();

                NativeMethods.bls_get_public_key(context.ToBuffer(keyData), out var publicKey, out var error);
                context.ThrowOnError(error);

                PublicKey = context.ToReadOnlyCollection(publicKey);
            }
            else if (keyData.Length == PublicKeySize)
            {
                PublicKey = new ReadOnlyCollection<byte>(keyData);
            }
            else
            {
                throw new BbsException("Invalid key size");
            }
        }

        /// <summary>
        /// Raw public key value for the key pair
        /// </summary>
        /// <returns></returns>
        public ReadOnlyCollection<byte> PublicKey { get; internal set; }

        /// <summary>
        /// Raw secret/private key value for the key pair
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public ReadOnlyCollection<byte>? SecretKey { get; internal set; }

        /// <summary>
        /// Generates new BBS+ public key from the current BLS12-381
        /// </summary>
        /// <param name="messageCount">The message count.</param>
        /// <returns></returns>
        public BbsKeyPair GeyBbsKeyPair(uint messageCount)
        {
            using var context = new UnmanagedMemoryContext();

            if (SecretKey is null)
            {
                NativeMethods.bls_public_key_to_bbs_key(context.ToBuffer(PublicKey), messageCount, out var publicKey, out var error);
                context.ThrowOnError(error);

                return new BbsKeyPair(context.ToByteArray(publicKey), messageCount);
            }
            else
            {
                NativeMethods.bls_secret_key_to_bbs_key(context.ToBuffer(SecretKey), messageCount, out var publicKey, out var error);
                context.ThrowOnError(error);

                return new BbsKeyPair(context.ToByteArray(publicKey), messageCount);
            }
        }
    }
}