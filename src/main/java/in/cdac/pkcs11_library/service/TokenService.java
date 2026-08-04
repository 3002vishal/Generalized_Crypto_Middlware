package in.cdac.pkcs11_library.service;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.NativeLongByReference;
import in.cdac.pkcs11_library.model.TokenInfo;
import in.cdac.pkcs11_library.pkcs11.CK_TOKEN_INFO;
import in.cdac.pkcs11_library.pkcs11.PKCS11Library;
import org.springframework.stereotype.Service;


import java.util.ArrayList;
import java.util.List;


public class TokenService {

    private final PKCS11Library pkcs11;

    public TokenService(String dllPath) {
        this.pkcs11 = PKCS11Library.load(dllPath);
    }

    public void initialize() {

        NativeLong rv = pkcs11.C_Initialize(null);

        System.out.println("Return Value: " + rv.longValue());

        if (rv.longValue() == 0) {
            System.out.println("PKCS#11 Initialized Successfully");
        } else {
            System.out.println("Initialization Failed");
        }
    }

    public void finalizeLibrary() {

        NativeLong rv = pkcs11.C_Finalize(null);

        System.out.println("Finalize Return Value: " + rv.longValue());

        if (rv.longValue() == 0)
            System.out.println("PKCS#11 Finalized Successfully");
        else
            System.out.println("Finalize Failed");
    }

    public List<TokenInfo> getSlots() {

        List<TokenInfo> tokens = new ArrayList<>();
        NativeLongByReference slotCount = new NativeLongByReference();

        NativeLong rv = pkcs11.C_GetSlotList(
                true,
                null,
                slotCount);

        if (rv.longValue() != 0) {
            System.out.println("First call failed : " + rv.longValue());
            return new ArrayList<>();
        }

        long count = slotCount.getValue().longValue();

        System.out.println("Number of Slots : " + count);

        NativeLong[] slots = new NativeLong[(int) count];

        rv = pkcs11.C_GetSlotList(
                true,
                slots,
                slotCount);

        if (rv.longValue() != 0) {
            System.out.println("Second call failed : " + rv.longValue());
            return new ArrayList<>();
        }

        System.out.println("\nSlot IDs:");
        for (int i = 0; i < count; i++) {

            CK_TOKEN_INFO info = new CK_TOKEN_INFO();

            rv = pkcs11.C_GetTokenInfo(slots[i], info);

            if (rv.longValue() != 0)
                continue;

            info.read();

            String label = new String(info.label).trim();
            String manufacturer =
                    new String(info.manufacturerID).trim();
            String model =
                    new String(info.model).trim();
            String serial =
                    new String(info.serialNumber).trim();

            TokenInfo token = new TokenInfo(
                    slots[i].longValue(),
                    label,
                    manufacturer,
                    model,
                    serial
            );

            tokens.add(token);
        }
        return tokens;
    }
}