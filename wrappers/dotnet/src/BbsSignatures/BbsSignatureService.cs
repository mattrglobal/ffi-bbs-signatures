using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace BbsSignatures
{
    public class BbsSignatureService : IBbsSignatureService
    {
        public static int SignatureSize => NativeMethods.bbs_signature_size();

        public static int BlindSignatureSize => NativeMethods.bbs_blind_signature_size();

        /// <summary>
        /// Signs a set of messages with a BBS key pair and produces a BBS signature
        /// </summary>
        /// <param name="signRequest">Request for the sign operation</param>
        /// <returns>The raw signature value</returns>
        /// <exception cref="BbsException">
        /// Secret key not found
        /// or
        /// Messages cannot be null
        /// </exception>
        public byte[] Sign(SignRequest signRequest)
        {
            if (signRequest?.KeyPair?.SecretKey is null) throw new BbsException("Secret key not found");
            if (signRequest?.Messages is null) throw new BbsException("Messages cannot be null");

            var bbsKeyPair = signRequest.KeyPair.GetBbsKey((uint)signRequest.Messages.Length);

            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_sign_context_init(out var error);
            context.ThrowOnError(error);

            foreach (var message in signRequest.Messages)
            {
                NativeMethods.bbs_sign_context_add_message_string(handle, message, out error);
                context.ThrowOnError(error);
            }

            NativeMethods.bbs_sign_context_set_public_key(handle, context.ToBuffer(bbsKeyPair.PublicKey), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_sign_context_set_secret_key(handle, context.ToBuffer(signRequest.KeyPair.SecretKey!), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_sign_context_finish(handle, out var signature, out error);
            context.ThrowOnError(error);

            return context.ToByteArray(signature);
        }

        /// <summary>
        /// Verifies a BBS+ signature for a set of messages with a BBS public key
        /// </summary>
        /// <param name="verifyRequest">Request for the signature verification operation</param>
        /// <returns>
        /// A result indicating if the signature was verified
        /// </returns>
        public bool Verify(VerifyRequest verifyRequest)
        {
            var bbsKeyPair = verifyRequest.KeyPair.GetBbsKey((uint)verifyRequest.Messages.Length);
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_verify_context_init(out var error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_context_set_public_key(handle, context.ToBuffer(bbsKeyPair.PublicKey), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_context_set_signature(handle, context.ToBuffer(verifyRequest.Signature), out error);
            context.ThrowOnError(error);

            foreach (var message in verifyRequest.Messages)
            {
                NativeMethods.bbs_verify_context_add_message_string(handle, message, out error);
                context.ThrowOnError(error);
            }

            var result = NativeMethods.bbs_verify_context_finish(handle, out error);
            context.ThrowOnError(error);

            return result == 0;
        }

        /// <summary>
        /// Signs a set of messages featuring both known and blinded messages to the signer and produces a BBS+ signature
        /// </summary>
        /// <param name="keyPair">The signing key containing the secret BLS key.</param>
        /// <param name="commitment">The commitment.</param>
        /// <param name="messages">The messages.</param>
        /// <returns></returns>
        public byte[] BlindSign(BlindSignRequest request)
        {
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_blind_sign_context_init(out var error);
            context.ThrowOnError(error);

            foreach (var item in request.Messages)
            {
                NativeMethods.bbs_blind_sign_context_add_message_string(handle, item.Index, item.Message, out error);
                context.ThrowOnError(error);
            }

            NativeMethods.bbs_blind_sign_context_set_public_key(handle, context.ToBuffer(request.Key), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_blind_sign_context_set_secret_key(handle, context.ToBuffer(request.KeyPair.SecretKey.ToArray()), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_blind_sign_context_set_commitment(handle, context.ToBuffer(request.Commitment), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_blind_sign_context_finish(handle, out var blindedSignature, out error);
            context.ThrowOnError(error);

            return context.ToByteArray(blindedSignature);
        }

        /// <summary>
        /// Unblinds the signature asynchronous.
        /// </summary>
        /// <param name="request">Unbling signature request</param>
        /// <returns></returns>
        public byte[] UnblindSignature(UnblindSignatureRequest request)
        {
            using var context = new UnmanagedMemory();

            NativeMethods.bbs_unblind_signature(context.ToBuffer(request.BlindedSignature), context.ToBuffer(request.BlindingFactor), out var unblindedSignature, out var error);
            context.ThrowOnError(error);

            return context.ToByteArray(unblindedSignature);
        }

        /// <summary>
        /// Create a blinded commitment of messages for use in producing a blinded BBS+ signature
        /// </summary>
        /// <param name="request">Request for producing the blinded commitment</param>
        /// <returns></returns>
        public BlindedCommitment CreateBlindedCommitment(CreateBlindedCommitmentRequest request)
        {
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_blind_commitment_context_init(out var error);
            context.ThrowOnError(error);

            foreach (var item in request.Messages)
            {
                NativeMethods.bbs_blind_commitment_context_add_message_string(handle, item.Index, item.Message, out error);
                context.ThrowOnError(error);
            }

            NativeMethods.bbs_blind_commitment_context_set_nonce_bytes(handle, context.ToBuffer(request.Nonce), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_blind_commitment_context_set_public_key(handle, context.ToBuffer(request.Key), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_blind_commitment_context_finish(handle, out var commitment, out var outContext, out var blindingFactor, out error);
            context.ThrowOnError(error);

            return new BlindedCommitment(context.ToByteArray(outContext), context.ToByteArray(blindingFactor), context.ToByteArray(commitment));
        }

        /// <summary>
        /// Verifies a blinded commitment of messages
        /// </summary>
        /// <param name="request">Request for the commitment verification</param>
        /// <returns></returns>
        public SignatureProofStatus VerifyBlindedCommitment(VerifyBlindedCommitmentRequest request)
        {
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_verify_blind_commitment_context_init(out var error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_blind_commitment_context_set_nonce_bytes(handle, context.ToBuffer(request.Nonce), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_blind_commitment_context_set_proof(handle, context.ToBuffer(request.Proof), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_blind_commitment_context_set_public_key(handle, context.ToBuffer(request.Key), out error);
            context.ThrowOnError(error);

            foreach (var index in request.BlindedIndices)
            {
                NativeMethods.bbs_verify_blind_commitment_context_add_blinded(handle, index, out error);
                context.ThrowOnError(error);
            }

            var result = NativeMethods.bbs_verify_blind_commitment_context_finish(handle, out error);
            context.ThrowOnError(error);

            return (SignatureProofStatus)result;
        }

        /// <summary>
        /// Creates the proof asynchronous.
        /// </summary>
        /// <param name="myKey">My key.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="messages">The messages.</param>
        /// <returns></returns>
        public byte[] CreateProof(CreateProofRequest proofRequest)
        {
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_create_proof_context_init(out var error);
            context.ThrowOnError(error);

            foreach (var message in proofRequest.Messages)
            {
                NativeMethods.bbs_create_proof_context_add_proof_message_string(handle, message.Message, message.ProofType, context.ToBuffer(proofRequest.BlindingFactor ?? Array.Empty<byte>()), out error);
                context.ThrowOnError(error);
            }

            NativeMethods.bbs_create_proof_context_set_nonce_bytes(handle, context.ToBuffer(proofRequest.Nonce), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_create_proof_context_set_public_key(handle, context.ToBuffer(proofRequest.Key), out error);

             context.ThrowOnError(error);

            NativeMethods.bbs_create_proof_context_set_signature(handle, context.ToBuffer(proofRequest.Signature), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_create_proof_context_finish(handle, out var proof, out error);
            context.ThrowOnError(error);

            return context.ToByteArray(proof);
        }

        /// <summary>
        /// Verifies a proof
        /// </summary>
        /// <param name="request">Verify proof request parameters</param>
        /// <returns></returns>
        public bool VerifyProof(VerifyProofRequest request)
        {
            using var context = new UnmanagedMemory();

            var handle = NativeMethods.bbs_verify_proof_context_init(out var error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_proof_context_set_public_key(handle, context.ToBuffer(request.Key), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_proof_context_set_nonce_bytes(handle, context.ToBuffer(request.Nonce), out error);
            context.ThrowOnError(error);

            NativeMethods.bbs_verify_proof_context_set_proof(handle, context.ToBuffer(request.Proof), out error);
            context.ThrowOnError(error);

            foreach (var item in request.Messages)
            {
                NativeMethods.bbs_verify_proof_context_add_message_string(handle, item, out error);
                context.ThrowOnError(error);
            }

            var result = NativeMethods.bbs_verify_proof_context_finish(handle, out error);
            context.ThrowOnError(error);

            return result == 0;
        }

        public int GetTotalMessageCount(byte[] proof)
        {
            using var context = new UnmanagedMemory();

            return NativeMethods.bbs_get_total_messages_count_for_proof(context.ToBuffer(proof));
        }
    }

    public interface IBbsSignatureService
    {
        byte[] Sign(SignRequest signRequest);

        bool Verify(VerifyRequest verifyRequest);

        byte[] BlindSign(BlindSignRequest request);

        byte[] UnblindSignature(UnblindSignatureRequest request);

        BlindedCommitment CreateBlindedCommitment(CreateBlindedCommitmentRequest request);

        SignatureProofStatus VerifyBlindedCommitment(VerifyBlindedCommitmentRequest request);

        byte[] CreateProof(CreateProofRequest proofRequest);

        bool VerifyProof(VerifyProofRequest request);

        int GetTotalMessageCount(byte[] proof);
    }
}