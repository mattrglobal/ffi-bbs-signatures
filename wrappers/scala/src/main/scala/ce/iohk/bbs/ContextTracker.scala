package ce.iohk.bbs

import ce.iohk.bbs.BbsPlus.{EExternError, ErrorCodeMsg}

trait ContextTracker {
  private val lock: Object = new Object
  private var handleClosed: Boolean = false

  private def close(): Unit = handleClosed = true

  private def checkIfAlreadyClosed[T](t: => EExternError[T]): EExternError[T] = if (!handleClosed) t else {
    Left(ErrorCodeMsg(1000, s"${this.getClass.getName} handle already closed ...!"))
  }

  def synced[T](t: => EExternError[T]): EExternError[T] = lock.synchronized(checkIfAlreadyClosed(t))

  def syncedAndClose[T](t: => EExternError[T]): EExternError[T] = synced {
    close()
    t
  }
}
