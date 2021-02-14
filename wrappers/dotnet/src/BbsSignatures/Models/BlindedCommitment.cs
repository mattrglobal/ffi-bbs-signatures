using System.Collections.ObjectModel;

namespace BbsSignatures
{
    public class BlindedCommitment
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="BlindedCommitment"/> class.
        /// </summary>
        /// <param name="blindedSignContext">The blinded sign context.</param>
        /// <param name="blindingFactor">The blinding factor.</param>
        /// <param name="commitment">The commitment.</param>
        public BlindedCommitment(byte[] blindedSignContext, byte[] blindingFactor, byte[] commitment)
        {
            BlindSignContext = new ReadOnlyCollection<byte>(blindedSignContext);
            BlindingFactor = new ReadOnlyCollection<byte>(blindingFactor);
            Commitment = new ReadOnlyCollection<byte>(commitment);
        }

        /// <summary>
        /// Gets the blind sign context.
        /// </summary>
        /// <value>
        /// The blind sign context.
        /// </value>
        public ReadOnlyCollection<byte> BlindSignContext { get; internal set; }

        /// <summary>
        /// Gets the blinding factor.
        /// </summary>
        /// <value>
        /// The blinding factor.
        /// </value>
        public ReadOnlyCollection<byte> BlindingFactor { get; internal set; }

        /// <summary>
        /// Gets the commitment.
        /// </summary>
        /// <value>
        /// The commitment.
        /// </value>
        public ReadOnlyCollection<byte> Commitment { get; internal set; }
    }
}