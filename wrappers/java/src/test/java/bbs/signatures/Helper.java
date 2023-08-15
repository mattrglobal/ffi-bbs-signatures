package bbs.signatures;

public class Helper {
    static void debugPrint(String name, byte[] bytes){
        StringBuffer sb = new StringBuffer();
        sb.append("debug - ").append(name).append("[").append(bytes.length).append("] = ");
        for (int b : bytes) {
            if (b < 0) b += 256;
            sb.append(b).append(", ");
        }
        sb.delete(Math.max(0,sb.length()-2), sb.length());
        System.out.println(sb);
    }
}
