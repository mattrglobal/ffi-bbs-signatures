using System.Threading.Tasks;
using NUnit.Framework;

namespace Hyperledger.Ursa.BbsSignatures.Tests
{
    public class BbsBlindCommitmentTests
    {
        public IBbsSignatureService Service { get; }

        public BbsBlindCommitmentTests()
        {
            Service = new BbsSignatureService();
        }

        [Test(Description = "Get blinded signature size")]
        public void GetBbsBlindSignatureSize()
        {
            var result = NativeMethods.bbs_blind_signature_size();

            Assert.AreEqual(expected: 112, actual: result);
        }

        [Test(Description = "Create blinded commitment")]
        public void BlindCommitmentSingleMessageUsingApi()
        {
            var myKey = Service.GenerateBlsKey();
            var publicKey = myKey.GeyBbsKeyPair(1);

            var commitment = Service.CreateBlindedCommitment(new CreateBlindedCommitmentRequest(
                publicKey: publicKey,
                messages: new[] { new IndexedMessage { Index = 0, Message = "message_0" } },
                nonce: "123"));

            Assert.NotNull(commitment);
            Assert.NotNull(commitment.BlindingFactor);
            Assert.NotNull(commitment.BlindSignContext);
            Assert.NotNull(commitment.Commitment);
        }
    }
}
