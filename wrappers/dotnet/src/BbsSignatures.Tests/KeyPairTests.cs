using System;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;

namespace BbsSignatures.Tests
{
    public class KeyPairTests
    {
        public IBbsSignatureService Service { get; }

        public KeyPairTests()
        {
            Service = new BbsSignatureService();
        }

        [Test(Description = "Get BLS secret key size")]
        public void GetSecretKeySize()
        {
            Assert.AreEqual(BlsKeyPair.SecretKeySize, 32);
        }

        [Test(Description = "Get BLS public key G1 size")]
        public void GetPublicKeyG1Size()
        {
            Assert.AreEqual(BlsKeyPair.PublicKeyG1Size, 48);
        }

        [Test(Description = "Get BLS public key G2 size")]
        public void GetPublicKeyG2Size()
        {
            Assert.AreEqual(BlsKeyPair.PublicKeyG2Size, 96);
        }

        [Test(Description = "Generate new BLS G2 key pair with seed")]
        public void GenerateG2KeyWithSeed()
        {
            var seed = "my seed";

            var actual = BlsKeyPair.GenerateG2(seed);

            Assert.NotNull(actual);
            Assert.NotNull(actual.SecretKey);
            Assert.NotNull(actual.PublicKey);
            Assert.True(actual.IsG2());
            Assert.False(actual.IsG1());
            Assert.AreEqual(BlsKeyPair.SecretKeySize, actual.SecretKey.Length);
            Assert.AreEqual(BlsKeyPair.PublicKeyG2Size, actual.PublicKey.Length);
        }

        [Test(Description = "Generate new BLS G1 key pair with seed")]
        public void GenerateG1KeyWithSeed()
        {
            var seed = "my seed";

            var actual = BlsKeyPair.GenerateG1(seed);

            Assert.NotNull(actual);
            Assert.NotNull(actual.SecretKey);
            Assert.NotNull(actual.PublicKey);
            Assert.True(actual.IsG1());
            Assert.False(actual.IsG2());
            Assert.AreEqual(BlsKeyPair.SecretKeySize, actual.SecretKey.Length);
            Assert.AreEqual(BlsKeyPair.PublicKeyG1Size, actual.PublicKey.Length);
        }

        [Test(Description = "Generate BLS key pair without seed using wrapper class")]
        public void GenerateBlsKeyWithoutSeed()
        {
            var blsKeyPair = BlsKeyPair.GenerateG2();
            var dPublicKey = blsKeyPair.PublicKey;

            Assert.NotNull(blsKeyPair);
            Assert.NotNull(dPublicKey);
            Assert.NotNull(blsKeyPair.SecretKey);

            Assert.AreEqual(96, dPublicKey.Length);
            Assert.AreEqual(32, blsKeyPair.SecretKey.Length);
        }

        [Test(Description = "Generate new Blinded BLS G2 key pair with seed")]
        public void GenerateBlindedG2KeyWithSeed()
        {
            var seed = "my seed";

            var actual = BlindedBlsKeyPair.GenerateG2(seed);

            Assert.NotNull(actual);
            Assert.NotNull(actual.SecretKey);
            Assert.NotNull(actual.PublicKey);
            Assert.NotNull(actual.BlindingFactor);
            Assert.True(actual.IsG2());
            Assert.False(actual.IsG1());
            Assert.AreEqual(BlsKeyPair.SecretKeySize, actual.SecretKey.Length);
            Assert.AreEqual(BlsKeyPair.PublicKeyG2Size, actual.PublicKey.Length);
            Assert.AreEqual(BlindedBlsKeyPair.BlindingFactorSize, actual.BlindingFactor.Length);
        }

        [Test(Description = "Generate new Blinded BLS G1 key pair with seed")]
        public void GenerateBlindedG1KeyWithSeed()
        {
            var seed = "my seed";

            var actual = BlindedBlsKeyPair.GenerateG1(seed);

            Assert.NotNull(actual);
            Assert.NotNull(actual.SecretKey);
            Assert.NotNull(actual.PublicKey);
            Assert.NotNull(actual.BlindingFactor);
            Assert.False(actual.IsG2());
            Assert.True(actual.IsG1());
            Assert.AreEqual(BlsKeyPair.SecretKeySize, actual.SecretKey.Length);
            Assert.AreEqual(BlsKeyPair.PublicKeyG1Size, actual.PublicKey.Length);
            Assert.AreEqual(BlindedBlsKeyPair.BlindingFactorSize, actual.BlindingFactor.Length);
        }

        [Test(Description = "Create BBS public key from BLS secret key with message count 1")]
        public void CreateBbsKeyFromBlsSecretKey()
        {
            var secretKey = BlsKeyPair.GenerateG2();
            var publicKey = secretKey.GetBbsKey(1);

            Assert.NotNull(publicKey);
            Assert.AreEqual(196, publicKey.PublicKey.Length);
        }

        [Test(Description = "Create BBS public key from BLS public key with message count 1")]
        public void CreateBbsKeyFromBlsPublicKey()
        {
            var blsKeypair = BlsKeyPair.GenerateG2();
            var bbsKeyPair = new BlsKeyPair(blsKeypair.PublicKey.ToArray());

            Assert.IsNull(bbsKeyPair.SecretKey);

            var publicKey = bbsKeyPair.GetBbsKey(1);

            Assert.NotNull(publicKey);
            Assert.NotNull(bbsKeyPair.PublicKey);
            Assert.IsNull(bbsKeyPair.SecretKey);

            Assert.AreEqual(196, publicKey.PublicKey.Length);
            Assert.AreEqual(32, blsKeypair.SecretKey.Length);
        }
    }
}
