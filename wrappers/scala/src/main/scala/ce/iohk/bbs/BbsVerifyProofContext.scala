package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.{EExternError, ErrorCodeMsg}
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, Ops}
import ce.iohk.bbs.ErrorCodes.NoMessagesProvided

case class BbsVerifyProofContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsVerifyProofContext] = synced {
    api.bbsVerifyProofContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setNonce(nonce: Array[Byte]): EExternError[BbsVerifyProofContext] = synced {
    api.bbsVerifyProofContextSetNonceBytes(handle, nonce).map(_ => this)
  }

  def setProof(proof: Array[Byte]): EExternError[BbsVerifyProofContext] = synced {
    api.bbsVerifyProofContextSetProof(handle, proof).map(_ => this)
  }

  def addMessages(
                  messages: Seq[Array[Byte]],
                ): EExternError[BbsVerifyProofContext] = synced {

    def add(
             messages: Seq[Array[Byte]],
             acc: EExternError[BbsVerifyProofContext]): EExternError[BbsVerifyProofContext] = {
      if (messages.nonEmpty) {
        add(messages.tail, addMessage(messages.head))
      } else acc
    }

    if(messages.isEmpty) {
      Left(ErrorCodeMsg(NoMessagesProvided.id, NoMessagesProvided.toString))
    } else {
      add(messages.tail, addMessage(messages.head))
    }
  }


  def addMessage(
                  message: Array[Byte],
                ): EExternError[BbsVerifyProofContext] = synced {
    api.bbsVerifyProofContextAddMessageBytes(
      handle,
      message).map(_ => this)
  }

  def verify(): EExternError[Boolean] = syncedAndClose {
    api.bbsVerifyProofContextFinish(handle).map(_ => true)
  }

}

