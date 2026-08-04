package in.cdac.pkcs11_library.pkcs11;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

public interface PKCS11Library extends Library {

    // Load any PKCS#11 DLL
    static PKCS11Library load(String dllPath) {
        return Native.load(dllPath, PKCS11Library.class);
    }

    // PKCS#11 Functions
    NativeLong C_Initialize(Pointer pInitArgs);

    NativeLong C_Finalize(Pointer pReserved);

    NativeLong C_GetTokenInfo(
            NativeLong slotID,
            CK_TOKEN_INFO tokenInfo
    );

    NativeLong C_GetSlotList(
            boolean tokenPresent,
            NativeLong[] pSlotList,
            NativeLongByReference pulCount
    );
}
