using System;
using NUnit.Framework;

namespace BbsSignatures.Tests
{
    public class BbsSignTests
    {
        public IBbsSignatureService Service { get; }

        public BbsSignTests()
        {
            Service = new BbsSignatureService();
        }

        [Test(Description = "Get signature size")]
        public void GetSignatureSize()
        {
            var result = NativeMethods.bbs_signature_size();

            Assert.AreEqual(112, result);
        }

        [Test(Description = "Sign message")]
        public void SignSingleMessageUsingApi()
        {
            var myKey = BlsKeyPair.GenerateG2();

            var signature = Service.Sign(new SignRequest(myKey, new[] { "message" }));

            Assert.NotNull(signature);
            Assert.AreEqual(signature.Length, NativeMethods.bbs_signature_size());
        }

        [Test(Description = "Sign multiple messages")]
        public void SignMultipleeMessages()
        {
            var keyPair = BlsKeyPair.GenerateG2();

            var signature = Service.Sign(new SignRequest(keyPair, new[] { "message_1", "message_2" }));

            Assert.NotNull(signature);
            Assert.AreEqual(BbsSignatureService.SignatureSize, signature.Length);
        }

        [Test(Description = "Verify throws if invalid signature")]
        public void VerifyThrowsIfInvalidSignature()
        {
            var blsKeyPair = BlsKeyPair.GenerateG2();
            var bbsKeyPair = blsKeyPair.GetBbsKey(1);

            Assert.Throws<BbsException>(() => Service.Verify(new VerifyRequest(blsKeyPair, Array.Empty<byte>(), new[] { "message_0" })), "Signature cannot be empty array");
        }

        [Test(Description = "Sign message with one public key, verify with another")]
        public void SignAndVerifyDifferentKeys()
        {
            var keyPair = BlsKeyPair.GenerateG2();
            var messages = new[] { "message_1", "message_2" };

            var signature = Service.Sign(new SignRequest(keyPair, messages));

            var result = Service.Verify(new VerifyRequest(keyPair, signature, messages));
            Assert.True(result);
        }
    }
}
