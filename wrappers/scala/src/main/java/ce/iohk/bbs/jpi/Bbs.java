package ce.iohk.bbs.jpi;

import java.util.List;
public class Bbs {

    public static BbsJpi create(List<String> pathsToSearch, List<String> libsToLoad) {
        return BbsApiImpl.apply(pathsToSearch, libsToLoad);
    }
    public static BbsJpi create() {
        return BbsApiImpl.apply();
    }
}
