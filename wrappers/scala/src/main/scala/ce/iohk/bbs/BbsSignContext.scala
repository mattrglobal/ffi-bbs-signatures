package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, Ops}


case class BbsSignContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsSignContext] = synced {
    api.signContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setSecretKey(secretKey: Array[Byte]): EExternError[BbsSignContext] = synced {
    api.signContextSetSecretKey(handle, secretKey).map(_ => this)
  }

  def addMessages(messages: Array[Array[Byte]]): EExternError[BbsSignContext] = synced {
    api.signContextAddMessages(handle, messages) map (_ => this)
  }

  def addMessage(message: Array[Byte]): EExternError[BbsSignContext] = synced {
    api.signContextAddMessage(handle, message) map (_ => this)
  }

  def signature(): EExternError[Array[Byte]] = syncedAndClose {
    api.signContextFinish(handle)
  }
}

