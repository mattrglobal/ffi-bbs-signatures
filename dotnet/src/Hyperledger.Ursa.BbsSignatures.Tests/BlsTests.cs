using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Hyperledger.Ursa.BbsSignatures.Tests
{
    public class BlsTests
    {
        public IBbsSignatureService Service { get; }

        public BlsTests()
        {
            Service = new BbsSignatureService();
        }

        [Test(Description = "Get BLS secret key size")]
        public void GetSecretKeySize()
        {
            var actual = NativeMethods.bls_secret_key_size();

            Assert.AreEqual(actual, 32);
        }

        [Test(Description = "Get BLS public key size")]
        public void GetPublicKeySize()
        {
            var actual = NativeMethods.bls_public_key_size();

            Assert.AreEqual(actual, 96);
        }

        [Test(Description = "Generate new BLS key pair with seed")]
        public void GenerateKeyWithSeed()
        {
            var seed = new byte[] { 1, 2, 3 };

            var actual = Service.GenerateBlsKey(seed);

            Assert.NotNull(actual);
            Assert.NotNull(actual.SecretKey);
            Assert.NotNull(actual.PublicKey);
            Assert.AreEqual(32, actual.SecretKey.Count);
            Assert.AreEqual(96, actual.PublicKey.Count);
        }

        [Test(Description = "Generate BLS key pair without seed using wrapper class")]
        public void GenerateBlsKeyWithoutSeed()
        {
            var blsKeyPair = Service.GenerateBlsKey();
            var dPublicKey = blsKeyPair.PublicKey;

            Assert.NotNull(blsKeyPair);
            Assert.NotNull(dPublicKey);
            Assert.NotNull(blsKeyPair.SecretKey);

            Assert.AreEqual(96, dPublicKey.Count);
            Assert.AreEqual(32, blsKeyPair.SecretKey.Count);
        }

        [Test(Description = "Create BBS public key from BLS secret key with message count 1")]
        public void CreateBbsKeyFromBlsSecretKey()
        {
            var secretKey = Service.GenerateBlsKey();
            var publicKey = secretKey.GeyBbsKeyPair(1);

            Assert.NotNull(secretKey);
            Assert.NotNull(publicKey);
            Assert.NotNull(secretKey.SecretKey);

            Assert.AreEqual(196, publicKey.PublicKey.Count);
            Assert.AreEqual(32, secretKey.SecretKey.Count);
        }

        [Test(Description = "Create BBS public key from BLS public key with message count 1")]
        public void CreateBbsKeyFromBlsPublicKey()
        {
            var blsKeypair = Service.GenerateBlsKey();
            var bbsKeyPair = new BlsKeyPair(blsKeypair.PublicKey.ToArray());

            Assert.IsNull(bbsKeyPair.SecretKey);

            var publicKey = bbsKeyPair.GeyBbsKeyPair(1);

            Assert.NotNull(blsKeypair.SecretKey);
            Assert.NotNull(publicKey);
            Assert.NotNull(bbsKeyPair.PublicKey);
            Assert.IsNull(bbsKeyPair.SecretKey);

            Assert.AreEqual(196, publicKey.PublicKey.Count);
            Assert.AreEqual(32, blsKeypair.SecretKey.Count);
        }
    }
}
