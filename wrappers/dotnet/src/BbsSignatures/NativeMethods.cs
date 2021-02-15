using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;

namespace BbsSignatures
{
    [SuppressMessage("Style", "IDE1006:Naming Styles", Justification = "Names must match C callable methods")]
    internal class NativeMethods
    {
#if __IOS__
        internal const string BbsSignaturesLibrary = "__Internal";
#else
        internal const string BbsSignaturesLibrary = "bbs";
#endif

        #region Resources

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_string_free(IntPtr str);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_byte_buffer_free(ByteBuffer data);

        #endregion

        #region BLS

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_secret_key_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_public_key_g2_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int blinding_factor_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_public_key_g1_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_generate_g1_key(ByteBuffer seed, out ByteBuffer public_key, out ByteBuffer secret_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_generate_g2_key(ByteBuffer seed, out ByteBuffer public_key, out ByteBuffer secret_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_generate_blinded_g1_key(ByteBuffer seed, out ByteBuffer public_key, out ByteBuffer secret_key, out ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_generate_blinded_g2_key(ByteBuffer seed, out ByteBuffer public_key, out ByteBuffer secret_key, out ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_get_public_key(ByteBuffer secret_key, out ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_secret_key_to_bbs_key(ByteBuffer secret_key, uint message_count, out ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bls_public_key_to_bbs_key(ByteBuffer d_public_key, uint message_count, out ByteBuffer public_key, out ExternError err);

        #endregion

        #region BBS Blind Commitment

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_signature_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_blind_commitment_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_finish(ulong handle, out ByteBuffer commitment, out ByteBuffer out_context, out ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_add_message_string(ulong handle, uint index, string message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_add_message_bytes(ulong handle, uint index, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_add_message_prehashed(ulong handle, uint index, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_set_public_key(ulong handle, ByteBuffer value, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_set_nonce_string(ulong handle, string value, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_set_nonce_bytes(ulong handle, ByteBuffer value, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_commitment_context_set_nonce_prehashed(ulong handle, ByteBuffer value, out ExternError err);

        #endregion

        #region BBS Blind Sign

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_blind_sign_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_finish(ulong handle, out ByteBuffer blinded_signature, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_add_message_string(ulong handle, uint index, string message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_add_message_bytes(ulong handle, uint index, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_add_message_prehashed(ulong handle, uint index, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_set_secret_key(ulong handle, ByteBuffer secret_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_blind_sign_context_set_commitment(ulong handle, ByteBuffer commitment, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_unblind_signature(ByteBuffer blind_signature, ByteBuffer blinding_factor, out ByteBuffer unblind_signature, out ExternError err);

        #endregion

        #region BBS Create Proof

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_create_proof_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_finish(ulong handle, out ByteBuffer proof, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_add_proof_message_string(ulong handle, string message, ProofMessageType xtype, ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_add_proof_message_bytes(ulong handle, ByteBuffer message, ProofMessageType xtype, ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_add_proof_message_prehashed(ulong handle, ByteBuffer message, ProofMessageType xtype, ByteBuffer blinding_factor, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_set_signature(ulong handle, ByteBuffer signature, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_set_nonce_string(ulong handle, string nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_set_nonce_bytes(ulong handle, ByteBuffer nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_create_proof_context_set_nonce_prehashed(ulong handle, ByteBuffer nonce, out ExternError err);

        #endregion

        #region BBS Sign

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_signature_size();

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_sign_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_finish(ulong handle, out ByteBuffer signature, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_add_message_string(ulong handle, string message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_add_message_bytes(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_add_message_prehashed(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_sign_context_set_secret_key(ulong handle, ByteBuffer secret_key, out ExternError err);

        #endregion

        #region BBS Verify

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_verify_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_add_message_string(ulong handle, string message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_add_message_bytes(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_add_message_prehashed(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);
       
        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_set_signature(ulong handle, ByteBuffer signature, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_context_finish(ulong handle, out ExternError err);

        #endregion

        #region BBS Verify Proof

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_verify_proof_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_finish(ulong handle, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_add_message_string(ulong handle, string message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_add_message_bytes(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_add_message_prehashed(ulong handle, ByteBuffer message, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_set_proof(ulong handle, ByteBuffer proof, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_set_nonce_string(ulong handle, string nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_set_nonce_bytes(ulong handle, ByteBuffer nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_proof_context_set_nonce_prehashed(ulong handle, ByteBuffer nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_get_total_messages_count_for_proof(ByteBuffer proof);

        #endregion

        #region BBS Verify Blind Blind Commitment

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern ulong bbs_verify_blind_commitment_context_init(out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_add_blinded(ulong handle, uint index, out ExternError err);
        
        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_set_public_key(ulong handle, ByteBuffer public_key, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_set_nonce_string(ulong handle, string nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_set_nonce_bytes(ulong handle, ByteBuffer nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_set_nonce_prehashed(ulong handle, ByteBuffer nonce, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_set_proof(ulong handle, ByteBuffer proof, out ExternError err);

        [DllImport(BbsSignaturesLibrary, CharSet = CharSet.Ansi, BestFitMapping = false, ThrowOnUnmappableChar = true)]
        internal static extern int bbs_verify_blind_commitment_context_finish(ulong handle, out ExternError err);

        #endregion
    }
}
