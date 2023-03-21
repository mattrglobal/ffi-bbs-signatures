package ce.iohk.bbs

import ce.iohk.bbs.BbsPlus._
import ce.iohk.bbs.helper.ArrayStruct
import ce.iohk.bbs.helper.ArrayStruct.Ops._
import jnr.ffi.Pointer


object BbsPlusOps {

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

  implicit class Ops(val api: BbsPlus) extends AnyVal {

    private implicit def rt = api.runtime

    def makeInStruct(): Pointer = ArrayStruct.byteArrayStructIn(api.runtime)

    def createBlsKeyPair(seed: Array[Byte]): EExternError[BlsKeyPair] = {

      val sizePubKey = api.bls_public_key_g2_size()
      val sizePrivKey = api.bls_secret_key_size()
      println(s"Size pub = $sizePubKey size prive = $sizePrivKey")
      val pubKeyPtr = makeInStruct()
      val privKeyPtr = makeInStruct()
      val seedPtr = seed.toStructPointer
      val err = newExternErrorStruct
      val res = api.shim_bls_generate_g2_key(
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

    def newExternErrorStruct: ExternError = api.newExternErrorStruct()

    def bbsSignContextInit(): EExternError[BbsSignContext] = {
      val err = api.newExternErrorStruct()
      val result = api.bbs_sign_context_init(err)
      eitherExternErrorOr(err, 0, BbsSignContext(api, BbsHandle(result)))
    }

    def bbsBlindCommitmentContextInit(): EExternError[BbsBlindCommitmentContext] = {
      val err = api.newExternErrorStruct()
      val result = api.bbs_blind_commitment_context_init(err)
      eitherExternErrorOr(err, 0, BbsBlindCommitmentContext(api, BbsHandle(result)))
    }

    def bbsVerifyBlindCommitmentContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.bbs_verify_blind_commitment_context_finish(handle.handle, err)
      )
    }

    def bbsVerifyBlindCommitmentContextSetProof(handle: BbsHandle, proof: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.shim_bbs_verify_blind_commitment_context_set_proof(handle.handle, proof.toStructPointer, err)
      )
    }

    def bbsVerifyBlindCommitmentContextSetNonceBytes(handle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val result = api.shim_bbs_verify_blind_commitment_context_set_nonce_bytes(handle.handle, nonce.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsBlindSignContextInit(): EExternError[BbsBlindSignContext] = {
      val err = api.newExternErrorStruct()
      val result = api.bbs_blind_sign_context_init(err)
      eitherExternErrorOr(err, 0, BbsBlindSignContext(api, BbsHandle(result)))
    }

    def bbsBlindSignContextAddMessageBytes(handle: BbsHandle, index: Int, message: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.shim_bbs_blind_sign_context_add_message_bytes(handle.handle, index, message.toStructPointer, err)
      )
    }

    def bbsUnblindSignature(blindSig: Array[Byte], blindingFactor: Array[Byte]): EExternError[Array[Byte]] = {
      val err = api.newExternErrorStruct()
      val unblind_sig = makeInStruct()
      val result = api.shim_bbs_unblind_signature(blindSig.toStructPointer,
        blindingFactor.toStructPointer, unblind_sig, err)
      eitherExternErrorOr(
        err,
        result,
        unblind_sig.toByteAry
      )
    }

    def bbsVerifyContextInit(): EExternError[BbsVerifyContext] = {
      val err = api.newExternErrorStruct()
      val handle = api.bbs_verify_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyContext(api, BbsHandle(handle)))
    }

    def bbsVerifyProofContextInit(): EExternError[BbsVerifyProofContext] = {
      val err = api.newExternErrorStruct()
      val handle = api.bbs_verify_proof_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyProofContext(api, BbsHandle(handle)))
    }

    def bbsVerifyProofContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_proof_context_set_public_key(
        handle.handle,
        publicKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextSetNonceBytes(handle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_proof_context_set_nonce_bytes(
        handle.handle,
        nonce.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.bbs_verify_proof_context_finish(handle.handle, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextSetProof(handle: BbsHandle, proof: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_proof_context_set_proof(
        handle.handle,
        proof.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyProofContextAddMessageBytes(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_proof_context_add_message_bytes(
        handle.handle, message.toStructPointer, err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextInit(): EExternError[BbsCreateProofContext] = {
      val err = api.newExternErrorStruct()
      val handle = api.bbs_create_proof_context_init(err)
      eitherExternErrorOr(err, 0, BbsCreateProofContext(api, BbsHandle(handle)))
    }

    def bbsCreateProofContextSetSignature(bbsHandle: BbsHandle, sig: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_create_proof_context_set_signature(bbsHandle.handle, sig.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextSetPublicKey(bbsHandle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_create_proof_context_set_public_key(bbsHandle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextFinish(bbsHandle: BbsHandle): EExternError[Array[Byte]] = {
      val err = api.newExternErrorStruct()
      val proof = makeInStruct()
      val res = api.bbs_create_proof_context_finish(bbsHandle.handle, proof, err)
      eitherExternErrorOr(err, res, proof.toByteAry)
    }

    def bbsCreateProofContextSetNonceBytes(bbsHandle: BbsHandle, nonce: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_create_proof_context_set_nonce_bytes(bbsHandle.handle, nonce.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsCreateProofContextAddMessageBytes(bbsHandle: BbsHandle,
                                             message: Array[Byte],
                                             proofMessageType: ProofMessageType,
                                             blindingFactor: Array[Byte]
                                            ): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_create_proof_context_add_proof_message_bytes(
        bbsHandle.handle, message.toStructPointer, proofMessageType, blindingFactor.toStructPointer, err
      )
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextAddMessageBytes(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_context_add_message_bytes(handle.handle, message.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextSetSignature(handle: BbsHandle, sig: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.shim_bbs_verify_context_set_signature(handle.handle, sig.toStructPointer, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextFinish(handle: BbsHandle): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val res = api.bbs_verify_context_finish(handle.handle, err)
      eitherExternErrorOr(err, res)
    }

    def bbsVerifyContextAddMessages(handle: BbsHandle, messages: Array[Array[Byte]]): EExternError[Long] = {
      addMessages(handle, messages, bbsVerifyContextAddMessageBytes)
    }

    def bbsBlindSignContextSetCommitment(handle: BbsHandle, commitment: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val result = api.shim_bbs_blind_sign_context_set_commitment(handle.handle, commitment.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsBlindSignContextFinish(handle: BbsHandle): EExternError[Array[Byte]] = {
      val err = api.newExternErrorStruct()
      val blind_sig = makeInStruct()
      val res = api.bbs_blind_sign_context_finish(handle.handle, blind_sig, err)
      eitherExternErrorOr(
        err,
        res,
        blind_sig.toByteAry
      )
    }

    def bbsVerifyBlindCommitmentContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val result = api.shim_bbs_verify_blind_commitment_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      eitherExternErrorOr(err, result)
    }

    def bbsVerifyBlindCommitmentContextAddBlinded(handle: BbsHandle,
                                                  index: Int): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      val result = api.bbs_verify_blind_commitment_context_add_blinded(handle.handle, index, err)
      eitherExternErrorOr(err, result)
    }

    def bbsVerifyBlindCommitmentContextInit(): EExternError[BbsVerifyBlindCommitmentContext] = {
      val err = api.newExternErrorStruct()
      val result = api.bbs_verify_blind_commitment_context_init(err)
      eitherExternErrorOr(err, 0, BbsVerifyBlindCommitmentContext(api, BbsHandle(result)))
    }

    def bbsBlindCommitmentContextFinish(handle: BbsHandle
                                       ): EExternError[BlindCommitment] = {
      val err = api.newExternErrorStruct()
      val commitment = makeInStruct()
      val outContext = makeInStruct()
      val blindingFactor = makeInStruct()

      val res = api.bbs_blind_commitment_context_finish(
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
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.shim_bbs_blind_commitment_context_set_nonce_bytes(handle.handle, valueAry.toStructPointer, err)
      )
    }

    def bbsBlindCommitmentContextSetPublicKey(handle: BbsHandle, valueAry: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.shim_bbs_blind_commitment_context_set_public_key(handle.handle, valueAry.toStructPointer, err)
      )
    }

    def bbsBlindSignContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.shim_bbs_blind_sign_context_set_public_key(handle.handle, publicKey.toStructPointer, err)
      )
    }

    def bbsBlindSignContextSetSecretKey(handle: BbsHandle, secretKey: Array[Byte]): EExternError[Long] = {
      val err = api.newExternErrorStruct()
      eitherExternErrorOr(err,
        api.shim_bbs_blind_sign_context_set_secret_key(handle.handle, secretKey.toStructPointer, err)
      )
    }

    def bbsBlindCommitmentContextAddMessageBytes(handle: BbsHandle, index: Int, message: Array[Byte]): EExternError[Long] = {

      val err = api.newExternErrorStruct()
      eitherExternErrorOr(
        err,
        api.shim_bbs_blind_commitment_context_add_message_bytes(handle.handle,
          index,
          message.toStructPointer,
          err)
      )
    }

    def blsPublicKeyToBbsKey(publicKey: Array[Byte], messageLength: Int): EExternError[Array[Byte]] = {

      val err = api.newExternErrorStruct()
      val pKbb = publicKey.toStructPointer

      val out = api.makeInStruct()
      val res = api.shim_bls_public_key_to_bbs_key(
        pKbb,
        messageLength,
        out,
        err
      )

      eitherExternErrorOr(err, res, out.toByteAry)

    }


    def signContextSetPublicKey(handle: BbsHandle, publicKey: Array[Byte]): EExternError[Long] = {

      val err = api.newExternErrorStruct()

      val res = api.shim_bbs_sign_context_set_public_key(
        handle.handle,
        publicKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def signContextSetSecretKey(handle: BbsHandle, secretKey: Array[Byte]): EExternError[Long] = {


      val err = api.newExternErrorStruct()

      val res = api.shim_bbs_sign_context_set_secret_key(
        handle.handle,
        secretKey.toStructPointer,
        err
      )
      eitherExternErrorOr(err, res)
    }

    def signContextAddMessage(handle: BbsHandle, message: Array[Byte]): EExternError[Long] = {

      val err = api.newExternErrorStruct()
      val ptr = message.toStructPointer
      val res = api.shim_bbs_sign_context_add_message_bytes(
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
      addMessages(handle, messages, api.signContextAddMessage)
    }

    def signContextFinish(handle: BbsHandle): EExternError[Array[Byte]] = {


      val sig = makeInStruct()
      val err = api.newExternErrorStruct()

      val res = api.bbs_sign_context_finish(
        handle.handle,
        sig,
        err
      )

      eitherExternErrorOr(err, res, sig.toByteAry)
    }

    def bbsBlindSigSize(): Long = api.bbs_blind_signature_size()
  }

  implicit class EExternOp[T](val e: EExternError[T]) extends AnyVal {
    def unsafe: T = e.getOrElse(throw new RuntimeException("Unsafe!"))
  }
}
