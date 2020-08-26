using NUnit.Framework;
using System.Linq;

namespace Hyperledger.Ursa.BbsSignatures.Tests
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
            var key = Service.GenerateBlsKey();
            var publicKey = key.GeyBbsKeyPair(5);

            var nonce = "123";
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
                    new ProofMessage { Message = messages[1], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[2], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[3], ProofType = ProofMessageType.Revealed },
                    new ProofMessage { Message = messages[4], ProofType = ProofMessageType.Revealed }
                };
                var proofResult = Service.CreateProof(new CreateProofRequest(publicKey, proofMessages1, signature, null, nonce));

                Assert.NotNull(proofResult);

                // Verify proof of revealed messages
                var indexedMessages1 = new[]
                {
                    new IndexedMessage { Message = messages[0], Index = 0u },
                    new IndexedMessage { Message = messages[1], Index = 1u },
                    new IndexedMessage { Message = messages[2], Index = 2u },
                    new IndexedMessage { Message = messages[3], Index = 3u },
                    new IndexedMessage { Message = messages[4], Index = 4u }
                };
                var verifyResult1 = Service.VerifyProof(new VerifyProofRequest(publicKey, proofResult, indexedMessages1, nonce));

                Assert.AreEqual(SignatureProofStatus.Success, verifyResult1);
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
            var indexedMessages = new[]
            {
                new IndexedMessage { Message = messages[0], Index = 0u },
                new IndexedMessage { Message = messages[1], Index = 1u }
            };

            var verifyProofResult = Service.VerifyProof(new VerifyProofRequest(publicKey, proof, indexedMessages, nonce));

            Assert.AreEqual(SignatureProofStatus.Success, verifyProofResult);
        }
    }
}
