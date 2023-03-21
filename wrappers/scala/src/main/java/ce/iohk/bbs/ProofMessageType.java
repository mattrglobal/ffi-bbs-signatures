package ce.iohk.bbs;

import jnr.ffi.util.EnumMapper;

public enum ProofMessageType implements EnumMapper.IntegerEnum {

    Revealed (1),
    HiddenProofSpecificBlinding(2),
    HiddenExternalBlinding(3);

    private final int value;

    ProofMessageType(int value) {
        this.value = value;
    }

    @Override
    public int intValue() {
        return value;
    }
}
