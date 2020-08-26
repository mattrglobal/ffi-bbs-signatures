using System;
namespace Hyperledger.Ursa.BbsSignatures
{
    public class UnblindSignatureRequest
    {
        public UnblindSignatureRequest(byte[] blindedSignature, byte[] blindingFactor)
        {
            BlindedSignature = blindedSignature ?? throw new ArgumentNullException(nameof(blindedSignature));
            BlindingFactor = blindingFactor ?? throw new ArgumentNullException(nameof(blindingFactor));
        }

        public byte[] BlindedSignature { get; set; }

        public byte[] BlindingFactor { get; set; }
    }
}
