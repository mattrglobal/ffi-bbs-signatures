namespace Hyperledger.Ursa.BbsSignatures
{
    public class BlindedBlsKeyPair : BlsKeyPair
    {
        public BlindedBlsKeyPair(byte[] publicKey, byte[] secretKey, byte[] blindingFactor)
            : base(publicKey, secretKey)
        {
            BlindingFactor = blindingFactor;
        }

        public byte[] BlindingFactor { get; internal set; }

        public static BlindedBlsKeyPair GenerateG1(byte[]? seed = default)
        {
            using var context = new UnmanagedMemory();

            NativeMethods.bls_generate_blinded_g1_key(context.ToBuffer(seed), out var publicKey, out var secretKey, out var blindingFactor, out var error);
            context.ThrowOnError(error);

            return new BlindedBlsKeyPair(
                publicKey: context.ToByteArray(publicKey),
                secretKey: context.ToByteArray(secretKey),
                blindingFactor: context.ToByteArray(blindingFactor));
        }

        public static BlindedBlsKeyPair GenerateG2(byte[]? seed = default)
        {
            using var context = new UnmanagedMemory();

            NativeMethods.bls_generate_blinded_g2_key(context.ToBuffer(seed), out var publicKey, out var secretKey, out var blindingFactor, out var error);
            context.ThrowOnError(error);

            return new BlindedBlsKeyPair(
                publicKey: context.ToByteArray(publicKey),
                secretKey: context.ToByteArray(secretKey),
                blindingFactor: context.ToByteArray(blindingFactor));
        }
    }
}