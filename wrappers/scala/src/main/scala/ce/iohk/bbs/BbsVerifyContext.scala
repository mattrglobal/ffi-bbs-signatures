package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, Ops}

case class BbsVerifyContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsVerifyContext] = synced {
    api.bbsVerifyContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def addMessages(messages: Array[Array[Byte]]): EExternError[BbsVerifyContext] = synced {
    api.bbsVerifyContextAddMessages(handle, messages).map(_ => this)
  }

  def setSignature(signature: Array[Byte]): EExternError[BbsVerifyContext] = synced {
    api.bbsVerifyContextSetSignature(handle, signature).map(_ => this)
  }

  def addMessage(message: Array[Byte]): EExternError[BbsVerifyContext] = synced {
    api.bbsVerifyContextAddMessageBytes(handle, message).map(_ => this)
  }

  def verify(): EExternError[Boolean] = syncedAndClose {
    api.bbsVerifyContextFinish(handle) map (_ == 0)
  }
}
