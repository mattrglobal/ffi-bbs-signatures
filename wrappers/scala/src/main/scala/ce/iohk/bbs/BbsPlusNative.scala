package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.{FfiStr, Handle}
import jnr.ffi.{LibraryLoader, Pointer, Runtime}
import jnr.ffi.byref.PointerByReference
import jnr.ffi.types._

object BbsPlusNative {

  type EExternError[T] = Either[ErrorCodeMsg, T]
  type FfiStr = String
  type Handle = Long@u_int64_t
  case class ErrorCodeMsg(code: Long, message: String) extends Exception(s"code: $code, $message")

  def apply(): BbsPlusNative = apply(
    Seq(ClasspathSharedObject.createTempFolderWithExtractedLibs.toString)
  )

  def apply(pathsToSearch: Seq[String],
            libsToLoad: Seq[String] = ClasspathSharedObject.namesOfSharedObjectsToLoad): BbsPlusNative = {

    val withPathsToSearch = pathsToSearch.foldLeft(LibraryLoader.create(classOf[BbsPlusNative])) {
      case (acc, e) => acc.search(e)
    }
    val withLibsToLoadAndPathsToSearch = libsToLoad.foldLeft(withPathsToSearch) {
      case (acc, e) => acc.library(e)
    }

    withLibsToLoadAndPathsToSearch.load()

  }


  def externSuccess[T](t: T): EExternError[T] = Right(t)

  def eitherExternErrorOr(externError: ExternError, returnCode: Long): EExternError[Long] = {
    eitherExternErrorOr(externError, returnCode, returnCode)
  }

  def eitherExternErrorOr[T](externError: ExternError, returnCode: Long, t : => T): EExternError[T] = {
    if(externError.code.get() != 0) {
      Left(ErrorCodeMsg(externError.code.get(), externError.message.get()))
    } else if (returnCode != 0) {
      Left(ErrorCodeMsg(returnCode, s"Return code indicates failure $returnCode"))
    } else {
      Right(t)
    }
  }

}

trait BbsPlusNative {

  def runtime: Runtime = Runtime.getRuntime(BbsPlusNative.this)

  def bbs_blind_signature_size(): Long @int32_t

  def newExternErrorStruct(): ExternError = new ExternError(runtime)

  def bbs_blind_commitment_context_add_message_string(
                                                       handle: Handle,
                                                       index: Int@u_int32_t,
                                                       message: FfiStr,
                                                       err: ExternError): Long@int32_t

  def bls_secret_key_size(): Int @int32_t

  def bls_public_key_g2_size(): Int @int32_t

  def shim_bls_generate_g2_key(seed: Pointer,
                          public_key: Pointer,
                          secret_key: Pointer,
                          err: ExternError): Long@int32_t


  def bbs_blind_commitment_context_finish(handle: Long@u_int64_t,
                                          commitment: Pointer,
                                          out_context: Pointer,
                                          blinding_factor: Pointer,
                                          err: ExternError): Long@int32_t


  def shim_bbs_blind_commitment_context_set_nonce_bytes(handle: Long @u_int64_t,
                                                   valueAry: Pointer,
                                                   err: ExternError): Long @int32_t

  def shim_bbs_blind_commitment_context_set_public_key(handle: Long @u_int64_t,
    valueAry: Pointer ,
    err: ExternError): Int @int32_t

  def shim_bbs_blind_commitment_context_add_message_bytes( handle: Long @u_int64_t,
   index: Int @u_int32_t,
    message: Pointer,
    err: ExternError): Long @int32_t

  def bbs_blind_commitment_context_init(err: ExternError): Long @u_int64_t

  def bbs_verify_context_init(err: ExternError): Long @u_int64_t

  def bbs_verify_blind_commitment_context_init(err: ExternError): Long @u_int64_t

  def shim_bbs_verify_context_set_signature(handle: Long@u_int64_t,
                                            value: Pointer,
                                            err: ExternError): Long@int32_t

  def shim_bbs_create_proof_context_set_signature(handle: Long@u_int64_t,
                                            value: Pointer,
                                            err: ExternError): Long@int32_t

  def bbs_verify_context_finish(handle: Long@u_int64_t, err: ExternError): Long@int32_t

  def bbs_create_proof_context_finish(handle: Long@u_int64_t,
                                      proof: Pointer,
                                      err: ExternError): Long@int32_t

  def shim_bbs_verify_context_add_message_bytes(handle: Long@u_int64_t,
                                                message: Pointer,
                                                err: ExternError): Long@int32_t

    def bbs_verify_blind_commitment_context_add_blinded(handle: Long@u_int64_t,
                                                      index: Int@u_int32_t,
                                                      err: ExternError): Long@int32_t

  def shim_bbs_verify_blind_commitment_context_set_public_key(handle: Long@u_int64_t,
                                                         valueAry: Pointer,
                                                         err: ExternError): Long@int32_t


  def shim_bbs_blind_sign_context_add_message_bytes(handle: Long@u_int64_t,
                                                    index: Int@u_int32_t,
                                                    message: Pointer,
                                                    err: ExternError): Long@int32_t

  def shim_bbs_blind_sign_context_set_public_key(handle: Long@u_int64_t,
                                                 public_key: Pointer,
                                                    err: ExternError): Long@int32_t

  def shim_bbs_blind_sign_context_set_secret_key(handle: Long@u_int64_t,
                                                 secret_key: Pointer,
                                                 err: ExternError): Long@int32_t

  def shim_bbs_blind_sign_context_set_commitment(handle: Long@u_int64_t,
                                                 commitment: Pointer,
                                                 err: ExternError): Long@int32_t

  def bbs_blind_sign_context_finish(
                                     handle: Long@u_int64_t,
                                     blind_sig: Pointer,
                                     err: ExternError): Long@int32_t

  def bbs_blind_sign_context_init(err: ExternError): Long@u_int64_t

  def bbs_verify_blind_commitment_context_finish(handle: Long @u_int64_t, err: ExternError): Long@int32_t

  def shim_bbs_verify_blind_commitment_context_set_proof(handle: Long@u_int64_t,
                                                         valueAry: Pointer,
                                                         err: ExternError): Long@int32_t

  def shim_bbs_verify_blind_commitment_context_set_nonce_bytes(handle: Long@u_int64_t,
                                                               valueAry: Pointer,
                                                               err: ExternError
                                                              ): Long@int32_t

  def shim_bbs_unblind_signature(
                                  blind_sig: Pointer,
                                  blind_factor: Pointer,
                                  unblind_sig: Pointer,
                                  err: ExternError): Long@int32_t


  def shim_bls_generate_blinded_g2_key(seed: Pointer,
                                       public_key: Pointer ,
                                       secret_key: Pointer ,
                                       blinding_factor: Pointer ,
     err: ExternError): Long @int32_t

  def shim_err_code_to_str(err: PointerByReference, buf: StringBuffer): String


  def bbs_sign_context_init(err: ExternError): Long@u_int64_t
  def bbs_create_proof_context_init(err: ExternError): Long@u_int64_t
  def bbs_verify_proof_context_init(err: ExternError): Long@u_int64_t

  def shim_bbs_verify_proof_context_set_proof(handle: Long@u_int64_t,
                                              value: Pointer,
                                              err: ExternError): Long@int32_t

  def bbs_verify_proof_context_finish(handle: Long@u_int64_t, err: ExternError): Long@int32_t

  def shim_bbs_create_proof_context_add_proof_message_bytes(handle: Long@u_int64_t,
                                                            message: Pointer,
                                                            xtype: ProofMessageType,
                                                            blinding_factor: Pointer,
                                                            err: ExternError): Long@int32_t

  def shim_bls_public_key_to_bbs_key(
                                     d_public_key_len: Pointer,
                                     message_count: Int@u_int32_t,
                                     public_key: Pointer,
                                     err: ExternError): Long @int32_t

  def bbs_sign_context_finish(handle: Long@u_int64_t,
                              signature: Pointer,
                              err: ExternError): Int @int32_t

  def shim_bbs_sign_context_add_message_bytes(handle: Long @u_int64_t,
                                              message: Pointer,
                                              err: ExternError): Int @int32_t

  def shim_bbs_sign_context_set_public_key( handle: Long @u_int64_t,
                                            value: Pointer,
                                            err: ExternError ): Int @u_int32_t

  def shim_bbs_verify_context_set_public_key( handle: Long @u_int64_t,
                                            value: Pointer,
                                            err: ExternError ): Int @u_int32_t

  def shim_bbs_create_proof_context_set_public_key( handle: Long @u_int64_t,
                                              value: Pointer,
                                              err: ExternError ): Int @u_int32_t

  def shim_bbs_verify_proof_context_set_public_key( handle: Long @u_int64_t,
                                                    value: Pointer,
                                                    err: ExternError ): Int @u_int32_t

  def shim_bbs_create_proof_context_set_nonce_bytes(handle: Long@u_int64_t,
                                                    value: Pointer,
                                                    err: ExternError): Int@u_int32_t

  def shim_bbs_verify_proof_context_set_nonce_bytes(handle: Long@u_int64_t,
                                                    value: Pointer,
                                                    err: ExternError): Int@u_int32_t

  def shim_bbs_verify_proof_context_add_message_bytes(handle: Long@u_int64_t,
                                                      message: Pointer,
                                                      err: ExternError): Int@u_int32_t

  def shim_bbs_sign_context_set_secret_key( handle: Long @u_int64_t,
    value: Pointer,
    err: ExternError ): Int @u_int32_t

}
