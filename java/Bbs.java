class Bbs {
    private static native int bls_generate_g1_key(byte[] seed, byte[] blinding_factor, byte[] public_key, byte[] secret_key);

    static {
        System.loadLibrary("bbs");
    }

    public static void main(String[] args) {
        byte[] seed = new byte[32];
        byte[] blinding_factor = new byte[0];
        byte[] public_key = new byte[96];
        byte[] secret_key = new byte[32];
        bls_generate_g1_key(seed, blinding_factor, public_key, secret_key);
        System.out.println("Bbs");
    }
}
