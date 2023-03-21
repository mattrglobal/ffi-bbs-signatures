package ce.iohk.bbs.helper

import jnr.ffi.byref.PointerByReference
import jnr.ffi.{NativeLong, NativeType, Pointer, Runtime, Type, TypeAlias}

object ArrayStruct {

  object Ops {

    implicit class StringToPointer(val string:String) extends AnyVal {
      def toStructPointer(implicit rt: Runtime): Pointer = {
        byteArrayStructIn(rt, string.toCharArray.map(_.toByte))
      }
    }

    implicit class ByteAryToPointer(val ary:Array[Byte]) extends AnyVal {
      def toStructPointer(implicit rt: Runtime): Pointer = byteArrayStructIn(rt, ary)
    }

    implicit class ByteAryFromPointerRef(val pointer: Pointer) extends AnyVal {
      def toByteAry(implicit rt: Runtime): Array[Byte] = byteArrayStructOut(rt, pointer)
    }
  }

  def byteArrayStructIn(runtime: Runtime, ary:Array[Byte] = Array.emptyByteArray): Pointer = {

    val lenType = runtime.findType(TypeAlias.uintptr_t)
    val ptrSize: Int = lenType.size

    require(ptrSize == runtime.findType(TypeAlias.int64_t).size,
      "ByteArray and ByteBuffer use these types to store the array len, they must be the same size in order to use this memory for both types.")


    val structPointer: Pointer = runtime.getMemoryManager.allocateDirect(ptrSize * 2)
    structPointer.putInt(lenType, 0, ary.length.toLong)


    if(ary.nonEmpty) {
      val arrayPointer = runtime.getMemoryManager.allocateDirect(ary.length)
      arrayPointer.put(0, ary, 0, ary.length)
      structPointer.putAddress(ptrSize, arrayPointer.address)
    }

    structPointer

  }


  def byteArrayStructOut(runtime: Runtime, ptr: Pointer): Array[Byte] = {

    val len = ptr.getInt(0)

    val sizeInt = runtime.findType(NativeType.SLONG).size

    val ptrAry = Pointer.wrap(runtime, ptr.getAddress(sizeInt))

    val result = new Array[Byte](len)

    (0 until len) foreach (i =>
      result(i) = ptrAry.getByte(i)
      )

    result
  }
  def byteArrayStructOut(runtime: Runtime, pointerByReference: PointerByReference): Array[Byte] = {

    println("a")
    byteArrayStructOut(runtime, pointerByReference.getValue)

  }
}
