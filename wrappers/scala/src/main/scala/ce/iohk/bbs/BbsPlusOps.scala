package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative._
import ce.iohk.bbs.helper.ArrayStruct
import ce.iohk.bbs.helper.ArrayStruct.Ops._
import jnr.ffi.Pointer


object BbsPlusOps {

  case class BbsPlus(nativeApi: BbsPlusNative)

  case class BbsHandle(handle: Long)

  case class BlsKeyPair(
                         pub: Array[Byte],
                         priv: Array[Byte]
                       )

  case class BlindCommitment(
                              commitment: Array[Byte],
                              outContext: Array[Byte],
                              blindingFactor: Array[Byte]
                            ) {
    override def toString: String = s"commitment len ${commitment.length}, ${outContext.length}, ${blindingFactor.length}"
  }

  implicit class NativeOps(val api: BbsPlusNative) extends AnyVal {
    def makeInStruct(): Pointer = ArrayStruct.byteArrayStructIn(api.runtime)
  }

  implicit class Ops(val api: BbsPlus) extends AnyVal {

    private implicit def rt = api.nativeApi.runtime

    def createBlsKeyPair(seed: Array[Byte]): EExternError[BlsKeyPair] = {

      val sizePubKey = api.nativeApi.bls_public_key_g2_size()
      val sizePrivKey = api.nativeApi.bls_secret_key_size()

      val pubKeyPtr = api.nativeApi.makeInStruct()
      val privKeyPtr = api.nativeApi.makeInStruct()
      val seedPtr = seed.toStructPointer
      val err = newExternErrorStruct
      val res = api.nativeApi.shim_bls_generate_g2_key(
        seedPtr,
        pubKeyPtr,
        privKeyPtr,
        err
      )

      val pubKey = pubKeyPtr.toByteAry
      val privKey = privKeyPtr.toByteAry
      require(pubKey.length == sizePubKey, s"Wrong size public key, got ${pubKey.length}, expected $sizePubKey")
      require(privKey.length == sizePrivKey, s"Wrong size private key, got ${privKey.length}, expected $sizePrivKey")

      eitherExternErrorOr(err, res, BlsKeyPair(
        pubKey,
        privKey
      ))
    }

    private def newExternErrorStruct: ExternError = api.nativeApi.newExternErrorStruct()

    def bbsSignContextInit(): EExternError[BbsSignContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.bbs_sign_context_init(err)
      eitherExternErrorOr(err, 0, BbsSignContext(api, BbsHandle(result)))
    }

    def bbsBlindCommitmentContextInit(): EExternError[BbsBlindCommitmentContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.bbs_blind_commitment_context_init(err)
      eitherExternErrorOr(err, 0, BbsBlindCommitmentContext(api, BbsHandle(result)))
    }

    def bbsVerifyBlindCommitmentContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.nativeApi.bbs_verify_blind_commitment_context_finish(handle.handle, err)
      )
    }

    def bbsVerifyBlindCommitmentContextSetProof(handle: BbsHandle, proof: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.nativeApi.shim_bbs_verify_blind_commitment_context_set_proof(handle.handle, proof.toStructPointer, err)
      )
    }

    def bbsVerifyBlindCommitmentContextSetNonceBytes(handle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.shim_bbs_verify_blind_commitment_context_set_nonce_bytes(handle.handle, nonce.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsBlindSignContextInit(): EExternError[BbsBlindSignContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.bbs_blind_sign_context_init(err)
      eitherExternErrorOr(err, 0, BbsBlindSignContext(api, BbsHandle(result)))
    }

    def bbsBlindSignContextAddMessageBytes(handle: BbsHandle, index: Int, message: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.nativeApi.shim_bbs_blind_sign_context_add_message_bytes(handle.handle, index, message.toStructPointer, err)
      )
    }

    def bbsUnblindSignature(blindSig: Array[Byte], blindingFactor: Array[Byte]): EExternError[Array[Byte]] = {
      val err = api.nativeApi.newExternErrorStruct()
      val unblind_sig = api.nativeApi.makeInStruct()
      val result = api.nativeApi.shim_bbs_unblind_signature(blindSig.toStructPointer,
        blindingFactor.toStructPointer, unblind_sig, err)
      eitherExternErrorOr(
        err,
        result,
        unblind_sig.toByteAry
      )
    }

    def bbsVerifyContextInit(): EExternError[BbsVerifyContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val handle = api.nativeApi.bbs_verify_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyContext(api, BbsHandle(handle)))
    }

    def bbsVerifyProofContextInit(): EExternError[BbsVerifyProofContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val handle = api.nativeApi.bbs_verify_proof_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyProofContext(api, BbsHandle(handle)))
    }

    def bbsVerifyProofContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_proof_context_set_public_key(
        handle.handle,
        publicKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextSetNonceBytes(handle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_proof_context_set_nonce_bytes(
        handle.handle,
        nonce.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.bbs_verify_proof_context_finish(handle.handle, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextSetProof(handle: BbsHandle, proof: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_proof_context_set_proof(
        handle.handle,
        proof.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextAddMessageBytes(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_proof_context_add_message_bytes(
        handle.handle, message.toStructPointer, err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextInit(): EExternError[BbsCreateProofContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val handle = api.nativeApi.bbs_create_proof_context_init(err)
      eitherExternErrorOr(err, 0, BbsCreateProofContext(api, BbsHandle(handle)))
    }

    def bbsCreateProofContextSetSignature(bbsHandle: BbsHandle, sig: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_create_proof_context_set_signature(bbsHandle.handle, sig.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextSetPublicKey(bbsHandle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_create_proof_context_set_public_key(bbsHandle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextFinish(bbsHandle: BbsHandle): EExternError[Array[Byte]] = {
      val err = api.nativeApi.newExternErrorStruct()
      val proof = api.nativeApi.makeInStruct()
      val res = api.nativeApi.bbs_create_proof_context_finish(bbsHandle.handle, proof, err)
      eitherExternErrorOr(err, res, proof.toByteAry)
    }

    def bbsCreateProofContextSetNonceBytes(bbsHandle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_create_proof_context_set_nonce_bytes(bbsHandle.handle, nonce.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextAddMessageBytes(bbsHandle: BbsHandle,
                                             message: Array[Byte],
                                             proofMessageType: ProofMessageType,
                                             blindingFactor: Array[Byte]
                                            ): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_create_proof_context_add_proof_message_bytes(
        bbsHandle.handle, message.toStructPointer, proofMessageType, blindingFactor.toStructPointer, err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextAddMessageBytes(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_context_add_message_bytes(handle.handle, message.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextSetSignature(handle: BbsHandle, sig: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.shim_bbs_verify_context_set_signature(handle.handle, sig.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val res = api.nativeApi.bbs_verify_context_finish(handle.handle, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextAddMessages(handle: BbsHandle, messages: Array[Array[Byte]]): EExternError[Long] = {
      addMessages(handle, messages, bbsVerifyContextAddMessageBytes)
    }

    def bbsBlindSignContextSetCommitment(handle: BbsHandle, commitment: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.shim_bbs_blind_sign_context_set_commitment(handle.handle, commitment.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsBlindSignContextFinish(handle: BbsHandle): EExternError[Array[Byte]] = {
      val err = api.nativeApi.newExternErrorStruct()
      val blind_sig = api.nativeApi.makeInStruct()
      val res = api.nativeApi.bbs_blind_sign_context_finish(handle.handle, blind_sig, err)
      eitherExternErrorOr(
        err,
        res,
        blind_sig.toByteAry
      )
    }

    def bbsVerifyBlindCommitmentContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.shim_bbs_verify_blind_commitment_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsVerifyBlindCommitmentContextAddBlinded(handle: BbsHandle,
                                                  index: Int): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.bbs_verify_blind_commitment_context_add_blinded(handle.handle, index, err)
      eitherExternErrorOr(err, result)
    }

    def bbsVerifyBlindCommitmentContextInit(): EExternError[BbsVerifyBlindCommitmentContext] = {
      val err = api.nativeApi.newExternErrorStruct()
      val result = api.nativeApi.bbs_verify_blind_commitment_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyBlindCommitmentContext(api, BbsHandle(result)))
    }

    def bbsBlindCommitmentContextFinish(handle: BbsHandle
                                       ): EExternError[BlindCommitment] = {
      val err = api.nativeApi.newExternErrorStruct()
      val commitment = api.nativeApi.makeInStruct()
      val outContext = api.nativeApi.makeInStruct()
      val blindingFactor = api.nativeApi.makeInStruct()

      val res = api.nativeApi.bbs_blind_commitment_context_finish(
        handle.handle,
        commitment,
        outContext,
        blindingFactor,
        err)

      eitherExternErrorOr(
        err,
        res,
        BlindCommitment(
          commitment.toByteAry,
          outContext.toByteAry,
          blindingFactor.toByteAry
        )
      )

    }

    def bbsBlindCommitmentContextSetNonceBytes(handle: BbsHandle, valueAry: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.nativeApi.shim_bbs_blind_commitment_context_set_nonce_bytes(handle.handle, valueAry.toStructPointer, err)
      )
    }

    def bbsBlindCommitmentContextSetPublicKey(handle: BbsHandle, valueAry: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.nativeApi.shim_bbs_blind_commitment_context_set_public_key(handle.handle, valueAry.toStructPointer, err)
      )
    }

    def bbsBlindSignContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.nativeApi.shim_bbs_blind_sign_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      )
    }

    def bbsBlindSignContextSetSecretKey(handle: BbsHandle, secretKey: Array[Byte]): EExternError[Long] = {
      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.nativeApi.shim_bbs_blind_sign_context_set_secret_key(handle.handle, secretKey.toStructPointer, err)
      )
    }

    def bbsBlindCommitmentContextAddMessageBytes(handle: BbsHandle, index: Int, message: Array[Byte]): EExternError[Long] = {

      val err = api.nativeApi.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.nativeApi.shim_bbs_blind_commitment_context_add_message_bytes(handle.handle,
          index,
          message.toStructPointer,
          err)
      )
    }

    def blsPublicKeyToBbsKey(publicKey: Array[Byte], messageLength: Int): EExternError[Array[Byte]] = {

      val err = api.nativeApi.newExternErrorStruct()
      val pKbb = publicKey.toStructPointer

      val out = api.nativeApi.makeInStruct()
      val res = api.nativeApi.shim_bls_public_key_to_bbs_key(
        pKbb,
        messageLength,
        out,
        err
      )

      eitherExternErrorOr(err, res, out.toByteAry)

    }


    def signContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {

      val err = api.nativeApi.newExternErrorStruct()

      val res = api.nativeApi.shim_bbs_sign_context_set_public_key(
        handle.handle,
        publicKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def signContextSetSecretKey(handle: BbsHandle, secretKey: Array[Byte]): EExternError[Long] = {


      val err = api.nativeApi.newExternErrorStruct()

      val res = api.nativeApi.shim_bbs_sign_context_set_secret_key(
        handle.handle,
        secretKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def signContextAddMessage(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {

      val err = api.nativeApi.newExternErrorStruct()
      val ptr = message.toStructPointer
      val res = api.nativeApi.shim_bbs_sign_context_add_message_bytes(
        handle.handle,
        ptr,
        err
      )
      eitherExternErrorOr(err, res)
    }


    private def addMessages(handle: BbsHandle, messages: Array[Array[Byte]], adder: (BbsHandle, Array[Byte]) => EExternError[Long]): EExternError[Long] = {
      require(messages.length > 0, "No message available to add?")

      def addImpl(messages: Array[Array[Byte]]): EExternError[Long] = {
        if (messages.nonEmpty) {
          adder(handle, messages.head).flatMap(_ => addImpl(messages.tail))
        } else Right(0)
      }

      addImpl(messages)
    }

    def signContextAddMessages(handle: BbsHandle, messages: Array[Array[Byte]]): EExternError[Long] = {
      addMessages(handle, messages, signContextAddMessage)
    }

    def signContextFinish(handle: BbsHandle): EExternError[Array[Byte]] = {


      val sig = api.nativeApi.makeInStruct()
      val err = api.nativeApi.newExternErrorStruct()

      val res = api.nativeApi.bbs_sign_context_finish(
        handle.handle,
        sig,
        err
      )

      eitherExternErrorOr(err, res, sig.toByteAry)
    }

    def bbsBlindSigSize(): Long = api.nativeApi.bbs_blind_signature_size()
  }

  implicit class EExternOp[T](val e: EExternError[T]) extends AnyVal {
    def unsafe: T = e.getOrElse(throw new RuntimeException("Unsafe!"))
  }
}
