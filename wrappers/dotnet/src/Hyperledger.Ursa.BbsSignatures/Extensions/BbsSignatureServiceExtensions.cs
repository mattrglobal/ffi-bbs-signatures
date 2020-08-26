using System;
using System.Text;

namespace Hyperledger.Ursa.BbsSignatures
{
    public static class BbsSignatureServiceExtensions
    {
        /// <summary>
        /// Generates new <see cref="BlsKeyPair" /> using a input seed as string
        /// </summary>
        /// <param name="seed">The seed.</param>
        /// <returns></returns>
        public static BlsKeyPair GenerateBlsKey(this IBbsSignatureService service, string seed) => service.GenerateBlsKey(Encoding.UTF8.GetBytes(seed ?? throw new Exception("Seed cannot be null")));

        /// <summary>
        /// Generates new <see cref="BlsKeyPair"/> using a random seed.
        /// </summary>
        /// <returns></returns>
        public static BlsKeyPair GenerateBlsKey(this IBbsSignatureService service) => service.GenerateBlsKey(Array.Empty<byte>());
    }
}
