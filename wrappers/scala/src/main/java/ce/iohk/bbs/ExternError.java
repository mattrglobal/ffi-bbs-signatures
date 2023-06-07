package ce.iohk.bbs;

import jnr.ffi.Struct;
import jnr.ffi.Runtime;

public class ExternError extends Struct {

    public final Signed32 code = new Signed32();
    public final UTF8StringRef message = new UTF8StringRef(1024);

    public ExternError(Runtime runtime) {
        super(runtime);
    }

}

