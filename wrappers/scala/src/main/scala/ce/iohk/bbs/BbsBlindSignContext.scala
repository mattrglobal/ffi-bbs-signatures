package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.EExternError
import ce.iohk.bbs.BbsPlusOps.{BbsHandle, BbsPlus, Ops}

case class BbsBlindSignContext(api: BbsPlus, private val handle: BbsHandle) extends ContextTracker {

  def setPublicKey(bbsKey: Array[Byte]): EExternError[BbsBlindSignContext] = synced {
    api.bbsBlindSignContextSetPublicKey(handle, bbsKey).map(_ => this)
  }

  def setCommitment(commitment: Array[Byte]): EExternError[BbsBlindSignContext] = synced {
    api.bbsBlindSignContextSetCommitment(handle, commitment).map(_ => this)
  }

  def setSecretKey(secret: Array[Byte]): EExternError[BbsBlindSignContext] = synced {
    api.bbsBlindSignContextSetSecretKey(handle, secret).map(_ => this)
  }

  def addMessage(index: Int, message: Array[Byte]): EExternError[BbsBlindSignContext] = synced {
    api.bbsBlindSignContextAddMessageBytes(handle, index, message).map(_ => this)
  }

  def addMessages(startingIndex: Int, messages: Seq[Array[Byte]]): EExternError[BbsBlindSignContext] = synced {
    require(startingIndex > -1, "Cannot have a negative index")
    if (messages.nonEmpty) {
      addMessage(startingIndex, messages.head)
        .flatMap(_ => addMessages(startingIndex + 1, messages.tail))

    } else {
      Right(this)
    }
  }

  def signature(): EExternError[Array[Byte]] = syncedAndClose {
    api.bbsBlindSignContextFinish(handle)
  }
}

