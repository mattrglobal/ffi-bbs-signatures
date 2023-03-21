package ce.iohk.bbs;

import jnr.ffi.Struct;
import jnr.ffi.Runtime;

public class ExternError extends Struct {

    public final UTF8String message = new UTF8String(1024);
    public final Unsigned32 code = new Unsigned32();

    public ExternError(Runtime runtime) {
        super(runtime);
    }

}

