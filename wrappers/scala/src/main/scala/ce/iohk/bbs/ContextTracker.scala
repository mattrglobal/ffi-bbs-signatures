package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.{EExternError, ErrorCodeMsg}

trait ContextTracker {
  private val lock: Object = new Object
  private var handleClosed: Boolean = false

  private def close(): Unit = handleClosed = true

  private def checkIfAlreadyClosed[T](t: => EExternError[T]): EExternError[T] = if (!handleClosed) t else {
    Left(ErrorCodeMsg(ErrorCodes.HandleAlreadyClosed.id, s"${this.getClass.getName} handle already closed ...!"))
  }

  protected def synced[T](t: => EExternError[T]): EExternError[T] = lock.synchronized(checkIfAlreadyClosed(t))

  protected def syncedAndClose[T](t: => EExternError[T]): EExternError[T] = synced {
    close()
    t
  }
}
