package ce.iohk.bbs

import ce.iohk.bbs.BbsPlus.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BlindCommitment, Ops}


case class BbsBlindCommitmentContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setNonce(nonce: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextSetNonceBytes(handle, nonce).map(_ => this)
  }

  def addMessage(index: Int, message: Array[Byte]): EExternError[BbsBlindCommitmentContext] = synced {
    api.bbsBlindCommitmentContextAddMessageBytes(handle, index, message).map(_ => this)
  }

  def blindCommitment(): EExternError[BlindCommitment] = syncedAndClose {
    api.bbsBlindCommitmentContextFinish(handle)
  }
}