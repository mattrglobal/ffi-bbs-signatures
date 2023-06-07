package ce.iohk.bbs

object ErrorCodes extends Enumeration {
  type ErrorCodes = Value
  val HandleAlreadyClosed = Value(1000)
  val NoMessagesProvided = Value(1001)

}
