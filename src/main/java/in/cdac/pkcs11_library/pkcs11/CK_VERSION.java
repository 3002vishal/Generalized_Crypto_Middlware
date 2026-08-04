package in.cdac.pkcs11_library.pkcs11;

import com.sun.jna.Structure;
import java.util.List;

public class CK_VERSION extends Structure {

    public byte major;
    public byte minor;

    @Override
    protected List<String> getFieldOrder() {
        return List.of("major", "minor");
    }
}
