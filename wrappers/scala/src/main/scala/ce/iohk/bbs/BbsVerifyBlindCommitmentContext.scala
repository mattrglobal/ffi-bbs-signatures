package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, Ops}

case class BbsVerifyBlindCommitmentContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsVerifyBlindCommitmentContext] = synced {
    api.bbsVerifyBlindCommitmentContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setNonce(nonce: Array[Byte]): EExternError[BbsVerifyBlindCommitmentContext] = synced {
    api.bbsVerifyBlindCommitmentContextSetNonceBytes(handle, nonce).map(_ => this)
  }

  def setProof(proof: Array[Byte]): EExternError[BbsVerifyBlindCommitmentContext] = synced {
    api.bbsVerifyBlindCommitmentContextSetProof(handle, proof).map(_ => this)
  }

  def addBlinded(index: Int): EExternError[BbsVerifyBlindCommitmentContext] = synced {
    api.bbsVerifyBlindCommitmentContextAddBlinded(handle, index).map(_ => this)
  }

  def verify(): EExternError[Boolean] = syncedAndClose {
    api.bbsVerifyBlindCommitmentContextFinish(handle).map(_ == 0)
  }
}

