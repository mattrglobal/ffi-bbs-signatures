import java.nio.ByteBuffer;

class Bbs {
    private static native int bls_generate_g1_key(byte[] seed, byte[] public_key, byte[] secret_key);
    private static native int bls_generate_g2_key(byte[] seed, byte[] public_key, byte[] secret_key);
    private static native int bls_generate_blinded_g1_key(byte[] seed, byte[] blinding_factor, byte[] public_key, byte[] secret_key);
    private static native int bls_generate_blinded_g2_key(byte[] seed, byte[] blinding_factor, byte[] public_key, byte[] secret_key);
    private static native int bls_secret_key_to_bbs_key(byte[] secret_key, int message_count, ByteBuffer public_key);
    private static native int bls_public_key_to_bbs_key(byte[] short_public_key, int message_count, ByteBuffer public_key);
    private static native int bbs_sign(byte[] secret_key, byte[] public_key, byte[][] messages, int message_count, byte[] signature);

    static {
        System.loadLibrary("bbs");
    }

    public static void main(String[] args) {
        byte[] seed = new byte[32];
        byte[] blinding_factor = new byte[32];
        byte[] public_key = new byte[96];
        byte[] secret_key = new byte[32];
        bls_generate_blinded_g1_key(seed, blinding_factor, public_key, secret_key);
        System.out.println("Bbs");
    }
}
