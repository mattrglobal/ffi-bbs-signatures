using System.Threading.Tasks;
using NUnit.Framework;

namespace BbsSignatures.Tests
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
            var myKey = BlsKeyPair.GenerateG2();
            var publicKey = myKey.GetBbsKey(1);

            var commitment = Service.CreateBlindedCommitment(new CreateBlindedCommitmentRequest(
                publicKey: publicKey,
                messages: new[] { new IndexedMessage { Index = 0, Message = "message_0" } },
                nonce: new byte[] { 1, 2, 3 }));

            Assert.NotNull(commitment);
            Assert.NotNull(commitment.BlindingFactor);
            Assert.NotNull(commitment.BlindSignContext);
            Assert.NotNull(commitment.Commitment);
        }
    }
}
