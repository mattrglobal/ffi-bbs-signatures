package ce.iohk.bbs;

import jnr.ffi.Runtime;
import jnr.ffi.Struct;

import java.nio.ByteBuffer;

public class ByteArrayStruct extends Struct {

    public final uintptr_t length = new uintptr_t();
    public final Pointer data = new Pointer();

    ByteArrayStruct(Runtime rt, byte[] bb) {
        super(rt);
        length.set(bb.length);
        data.get().putPointer(0, getRuntime().getMemoryManager().newPointer(ByteBuffer.wrap(bb)));
    }
}
