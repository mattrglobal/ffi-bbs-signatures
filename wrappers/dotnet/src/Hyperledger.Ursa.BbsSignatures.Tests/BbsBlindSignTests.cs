﻿using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Hyperledger.Ursa.BbsSignatures.Tests
{
    public class BbsBlindSignTests
    {
        public BbsBlindSignTests()
        {
            Service = new BbsSignatureService();
        }

        public IBbsSignatureService Service { get; }

        [Test(Description = "Blind sign a message using API")]
        public void BlindSignSingleMessageUsingApi()
        {
            var myKey = Service.GenerateBlsKey();
            var publicKey = myKey.GeyBbsKeyPair(2);

            var messages = new[]
            {
                new IndexedMessage { Index = 0, Message = "message_0" },
                new IndexedMessage { Index = 1, Message = "message_1" }
            };
            var nonce = "123";

            var commitment = Service.CreateBlindedCommitment(new CreateBlindedCommitmentRequest(publicKey, messages, nonce));

            var blindSign = Service.BlindSign(new BlindSignRequest(myKey, publicKey, commitment.Commitment.ToArray(), messages));

            Assert.NotNull(blindSign);
        }

        [Test(Description = "Unblind a signature")]
        public void UnblindSignatureUsingApi()
        {
            var myKey = Service.GenerateBlsKey();
            var publicKey = myKey.GeyBbsKeyPair(2);

            var messages = new[]
            {
                new IndexedMessage { Index = 0, Message = "message_0" },
                new IndexedMessage { Index = 1, Message = "message_1" }
            };
            var nonce = "123";

            var commitment = Service.CreateBlindedCommitment(new CreateBlindedCommitmentRequest(publicKey, messages, nonce));

            var blindedSignature = Service.BlindSign(new BlindSignRequest(myKey, publicKey, commitment.Commitment.ToArray(), messages));

            var result = Service.UnblindSignature(new UnblindSignatureRequest(blindedSignature, commitment.BlindingFactor.ToArray()));

            Assert.NotNull(result);
        }
    }
}
