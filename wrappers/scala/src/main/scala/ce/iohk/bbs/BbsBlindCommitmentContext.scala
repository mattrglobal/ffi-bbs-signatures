package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, BlindCommitment, Ops}


case class BbsBlindCommitmentContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setNonce(nonce: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextSetNonceBytes(handle, nonce).map(_ => this)
  }

  def addMessages(messages: Array[Array[Byte]]): EExternError[BbsBlindCommitmentContext] = synced {
    messages.zipWithIndex.foldLeft[EExternError[BbsBlindCommitmentContext]](Right(this)) {
      case (acc, (msg, i)) => acc.flatMap(_ => addMessage(i, msg))
    }
  }

  def addMessage(index: Int, message: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextAddMessageBytes(handle, index, message).map(_ => this)
  }

  def blindCommitment(): EExternError[BlindCommitment] = syncedAndClose {
    api.bbsBlindCommitmentContextFinish(handle)
  }
}