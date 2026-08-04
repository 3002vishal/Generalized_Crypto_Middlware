package in.cdac.pkcs11_library.pkcs11;


import com.sun.jna.Structure;
import java.util.List;

public class CK_TOKEN_INFO extends Structure {

    public byte[] label = new byte[32];
    public byte[] manufacturerID = new byte[32];
    public byte[] model = new byte[16];
    public byte[] serialNumber = new byte[16];

    public long flags;

    public long ulMaxSessionCount;
    public long ulSessionCount;
    public long ulMaxRwSessionCount;
    public long ulRwSessionCount;

    public long ulMaxPinLen;
    public long ulMinPinLen;

    public long ulTotalPublicMemory;
    public long ulFreePublicMemory;

    public long ulTotalPrivateMemory;
    public long ulFreePrivateMemory;

    public CK_VERSION hardwareVersion;
    public CK_VERSION firmwareVersion;

    public byte[] utcTime = new byte[16];

    @Override
    protected List<String> getFieldOrder() {
        return List.of(
                "label",
                "manufacturerID",
                "model",
                "serialNumber",
                "flags",
                "ulMaxSessionCount",
                "ulSessionCount",
                "ulMaxRwSessionCount",
                "ulRwSessionCount",
                "ulMaxPinLen",
                "ulMinPinLen",
                "ulTotalPublicMemory",
                "ulFreePublicMemory",
                "ulTotalPrivateMemory",
                "ulFreePrivateMemory",
                "hardwareVersion",
                "firmwareVersion",
                "utcTime"
        );
    }
}
