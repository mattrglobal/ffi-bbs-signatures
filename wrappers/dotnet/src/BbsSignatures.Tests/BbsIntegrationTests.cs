using NUnit.Framework;
using System.Linq;

namespace BbsSignatures.Tests
{
    public class BbsIntegrationTests
    {
        public BbsIntegrationTests()
        {
            Service = new BbsSignatureService();
        }

        public IBbsSignatureService Service { get; }

        [Test(Description = "Full end-to-end test")]
        public void FullDemoTest()
        {
            var key = BlsKeyPair.GenerateG2();
            var publicKey = key.GetBbsKey(5);

            var nonce = new byte[] { 1, 2, 3 };
            var messages = new[]
            {
                "message_1",
                "message_2",
                "message_3",
                "message_4",
                "message_5"
            };

            {
                // Sign messages
                var signature = Service.Sign(new SignRequest(key, messages));

                Assert.NotNull(signature);
                Assert.AreEqual(BbsSignatureService.SignatureSize, signature.Length);

                // Verify messages
                var verifySignatureResult = Service.Verify(new VerifyRequest(key, signature, messages));

                Assert.True(verifySignatureResult);

                // Create proof
                var proofMessages1 = new[]
                {
                    new ProofMessage { Message = messages[0], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[1], ProofType = ProofMessageType.HiddenProofSpecificBlinding },
                    new ProofMessage { Message = messages[2], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[3], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[4], ProofType = ProofMessageType.HiddenProofSpecificBlinding }
                };

                var proofResult = Service.CreateProof(new CreateProofRequest(publicKey, proofMessages1, signature, null, nonce));

                Assert.NotNull(proofResult);

                // Verify proof of revealed messages
                var verifyResult1 = Service.VerifyProof(new VerifyProofRequest(publicKey, proofResult, proofMessages1.Where(x => x.ProofType == ProofMessageType.Revealed).Select(x => x.Message).ToArray(), nonce));

                Assert.IsTrue(verifyResult1);
            }

            // Create blinded commitment
            var blindedMessages = new[]
            {
                new IndexedMessage { Index = 0, Message = messages[0] }
            };
            var commitment = Service.CreateBlindedCommitment(new CreateBlindedCommitmentRequest(publicKey, blindedMessages, nonce));

            Assert.NotNull(commitment);

            // Verify blinded commitment
            var verifyResult = Service.VerifyBlindedCommitment(new VerifyBlindedCommitmentRequest(publicKey, commitment.BlindSignContext.ToArray(), new [] { 0u }, nonce));

            Assert.AreEqual(SignatureProofStatus.Success, verifyResult);

            // Blind sign
            var messagesToSign = new[]
            {
                new IndexedMessage { Index = 1, Message = messages[1] },
                new IndexedMessage { Index = 2, Message = messages[2] },
                new IndexedMessage { Index = 3, Message = messages[3] },
                new IndexedMessage { Index = 4, Message = messages[4] }
            };
            var blindedSignature = Service.BlindSign(new BlindSignRequest(key, publicKey, commitment.Commitment.ToArray(), messagesToSign));

            Assert.NotNull(blindedSignature);
            Assert.AreEqual(BbsSignatureService.BlindSignatureSize, blindedSignature.Length);

            // Unblind signature
            var unblindedSignature = Service.UnblindSignature(new UnblindSignatureRequest(blindedSignature, commitment.BlindingFactor.ToArray()));

            Assert.NotNull(unblindedSignature);
            Assert.AreEqual(BbsSignatureService.SignatureSize, unblindedSignature.Length);

            // Verify signature
            var verifyUnblindedSignatureResult = Service.Verify(new VerifyRequest(key, unblindedSignature, messages));

            Assert.True(verifyUnblindedSignatureResult);

            // Create proof
            var proofMessages = new[]
            {
                new ProofMessage { Message = messages[0], ProofType = ProofMessageType.Revealed },
                new ProofMessage { Message = messages[1], ProofType = ProofMessageType.Revealed },
                new ProofMessage { Message = messages[2], ProofType = ProofMessageType.HiddenExternalBlinding },
                new ProofMessage { Message = messages[3], ProofType = ProofMessageType.HiddenExternalBlinding },
                new ProofMessage { Message = messages[4], ProofType = ProofMessageType.HiddenExternalBlinding }
            };

            var proof = Service.CreateProof(new CreateProofRequest(
                publicKey: publicKey,
                messages: proofMessages,
                signature: unblindedSignature,
                blindingFactor: commitment.BlindingFactor.ToArray(),
                nonce: nonce));

            Assert.NotNull(proof);
            Assert.True(proof.Length > 0);

            // Verify proof
            var verifyProofMessages = proofMessages
                .Where(x => x.ProofType == ProofMessageType.Revealed)
                .Select(x => x.Message)
                .ToArray();
            var verifyProofResult = Service.VerifyProof(new VerifyProofRequest(publicKey, proof, verifyProofMessages, nonce));

            Assert.IsTrue(verifyProofResult);

            var messageCount = Service.GetTotalMessageCount(proof);

            Assert.AreEqual(5, messageCount);
        }
    }
}
