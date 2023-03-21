package ce.iohk.bbs

import ce.iohk.bbs.BbsPlus.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, Ops}

case class BbsCreateProofContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsCreateProofContext] = synced {
    api.bbsCreateProofContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setNonce(nonce: Array[Byte]): EExternError[BbsCreateProofContext] = synced {
    api.bbsCreateProofContextSetNonceBytes(handle, nonce).map(_ => this)
  }

  def setSignature(signature: Array[Byte]): EExternError[BbsCreateProofContext] = synced {
    api.bbsCreateProofContextSetSignature(handle, signature).map(_ => this)
  }

  def addMessage(
                  message: Array[Byte],
                  proofMessageType: ProofMessageType,
                  blindingFactor: Array[Byte]): EExternError[BbsCreateProofContext] = synced {
    api.bbsCreateProofContextAddMessageBytes(
      handle,
      message,
      proofMessageType,
      blindingFactor).map(_ => this)
  }

  def proof(): EExternError[Array[Byte]] = syncedAndClose {
    api.bbsCreateProofContextFinish(handle)
  }

}


