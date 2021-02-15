using System.Text;

namespace BbsSignatures
{
    public class BlindedBlsKeyPair : BlsKeyPair
    {
        /// <summary>
        /// Default BLS 12-381 private key length
        /// </summary>
        public static int BlindingFactorSize => NativeMethods.blinding_factor_size();

        public BlindedBlsKeyPair(byte[] publicKey, byte[] secretKey, byte[] blindingFactor)
            : base(publicKey, secretKey)
        {
            BlindingFactor = blindingFactor;
        }

        public byte[] BlindingFactor { get; internal set; }

        public static new BlindedBlsKeyPair GenerateG1(string? seed = default)
        {
            using var context = new UnmanagedMemory();

            NativeMethods.bls_generate_blinded_g1_key(
                seed is null ? ByteBuffer.None : context.ToBuffer(Encoding.UTF8.GetBytes(seed)),
                out var publicKey, out var secretKey,
                out var blindingFactor,
                out var error);
            context.ThrowOnError(error);

            return new BlindedBlsKeyPair(
                publicKey: context.ToByteArray(publicKey),
                secretKey: context.ToByteArray(secretKey),
                blindingFactor: context.ToByteArray(blindingFactor));
        }

        public static new BlindedBlsKeyPair GenerateG2(string? seed = default)
        {
            using var context = new UnmanagedMemory();

            NativeMethods.bls_generate_blinded_g2_key(
                seed is null ? ByteBuffer.None : context.ToBuffer(Encoding.UTF8.GetBytes(seed)),
                out var publicKey,
                out var secretKey,
                out var blindingFactor,
                out var error);
            context.ThrowOnError(error);

            return new BlindedBlsKeyPair(
                publicKey: context.ToByteArray(publicKey),
                secretKey: context.ToByteArray(secretKey),
                blindingFactor: context.ToByteArray(blindingFactor));
        }
    }
}