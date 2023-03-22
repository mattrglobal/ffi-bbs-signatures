package ce.iohk.bbs

import ce.iohk.bbs.BbsPlusNative.{EExternError, ErrorCodeMsg}

trait PrintUtil {

  def printIt[T](eo: EExternError[T], tag: String = ""): EExternError[T] = {

    if(!tag.isBlank) println(tag)

    eo match {
      case Left(value) =>
        printErr(value)
      case Right(ary: Array[_]) =>
        println(s"Ary len ${ary.length}")
      case Right(x) =>
        println(s"$x")
    }
    eo
  }

  def printIfErr[T](eo: EExternError[T]): Unit = {
    eo match {
      case Left(value) => printErr(value)
      case Right(_) =>
    }
  }

  def printErr(e: ErrorCodeMsg): Unit = {
    println(e.code)
    if (e.code != 0) {
      println(s"Err: ${e.message}")
    }
  }

}

object PrintUtil extends PrintUtil