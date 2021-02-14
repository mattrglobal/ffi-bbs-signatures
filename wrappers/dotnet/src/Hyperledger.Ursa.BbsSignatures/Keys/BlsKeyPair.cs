using System.Collections.ObjectModel;
using System.Text;

namespace BbsSignatures
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
        public BlsKeyPair(byte[] publicKey, byte[]? secretKey = default)
        {
            SecretKey = secretKey;
            PublicKey = publicKey;
        }

        /// <summary>
        /// Default BLS 12-381 public key length
        /// </summary>
        public static int PublicKeyG1Size => NativeMethods.bls_public_key_g1_size();

        /// <summary>
        /// Default BLS 12-381 public key length
        /// </summary>
        public static int PublicKeyG2Size => NativeMethods.bls_public_key_g2_size();

        /// <summary>
        /// Default BLS 12-381 private key length
        /// </summary>
        public static int SecretKeySize => NativeMethods.bls_secret_key_size();

        /// <summary>
        /// Raw public key value for the key pair
        /// </summary>
        /// <returns></returns>
        public byte[] PublicKey { get; internal set; }

        /// <summary>
        /// Raw secret/private key value for the key pair
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public byte[]? SecretKey { get; internal set; }

        /// <summary>
        /// Generates new BBS+ public key from the current BLS12-381
        /// </summary>
        /// <param name="messageCount">The message count.</param>
        /// <returns></returns>
        public BbsKey GetBbsKey(uint messageCount)
        {
            using var context = new UnmanagedMemory();

            if (SecretKey != null)
            {
                NativeMethods.bls_secret_key_to_bbs_key(context.ToBuffer(SecretKey), messageCount, out var publicKey, out var error);
                context.ThrowOnError(error);

                return new BbsKey(context.ToByteArray(publicKey), messageCount);
            }
            else if (IsG2())
            {
                NativeMethods.bls_public_key_to_bbs_key(context.ToBuffer(PublicKey), messageCount, out var publicKey, out var error);
                context.ThrowOnError(error);

                return new BbsKey(context.ToByteArray(publicKey), messageCount);
            }
            throw new BbsException("Cannot generate BbsKey from G1 public key");
        }

        /// <summary>
        /// Returns <c>true</c> if the current instance is of G2 cyclic group, otherwise <c>false</c>
        /// </summary>
        /// <returns></returns>
        public bool IsG2() => PublicKey.Length == PublicKeyG2Size;

        /// <summary>
        /// Returns <c>true</c> if the current instance is of G1 cyclic group, otherwise <c>false</c>
        /// </summary>
        /// <returns></returns>
        public bool IsG1() => PublicKey.Length == PublicKeyG1Size;

        /// <summary>
        /// Creates new <see cref="BlsKeyPair"/> using a input seed as string.
        /// </summary>
        /// <param name="seed">The seed.</param>
        /// <returns></returns>
        public static BlsKeyPair GenerateG1(string? seed = null)
        {
            using var context = new UnmanagedMemory();

            var result = NativeMethods.bls_generate_g1_key(
                seed is null ? ByteBuffer.None : context.ToBuffer(Encoding.UTF8.GetBytes(seed)),
                out var publicKey,
                out var secretKey,
                out var error);

            context.ThrowOnError(error);

            return new BlsKeyPair(context.ToByteArray(publicKey), context.ToByteArray(secretKey));
        }

        /// <summary>
        /// Creates new <see cref="BlsKeyPair"/> using a input seed as string.
        /// </summary>
        /// <param name="seed">The seed.</param>
        /// <returns></returns>
        public static BlsKeyPair GenerateG2(string? seed = null)
        {
            using var context = new UnmanagedMemory();

            var result = NativeMethods.bls_generate_g2_key(
                seed is null ? ByteBuffer.None : context.ToBuffer(Encoding.UTF8.GetBytes(seed)),
                out var publicKey,
                out var secretKey,
                out var error);

            context.ThrowOnError(error);

            return new BlsKeyPair(context.ToByteArray(publicKey), context.ToByteArray(secretKey));
        }
    }
}