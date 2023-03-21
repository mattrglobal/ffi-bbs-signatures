package ce.iohk.bbs

import ce.iohk.bbs.BbsPlus.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, Ops}

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

