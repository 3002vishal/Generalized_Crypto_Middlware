package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.model.TokenInfo;
import in.cdac.pkcs11_library.model.Vendor;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Service
public class VendorScannerService {

    public List<TokenInfo> connectedTokens = new ArrayList<>();

    private List<Vendor> getSupportedVendors(){
        List<Vendor> vendors = new ArrayList<>();

        vendors.add(
                new Vendor(
                        "SafeSign",
                        "C:\\Windows\\System32\\aetpkss1.dll"
                )
        );

        vendors.add(
                new Vendor(
                        "eMudhra",
                        "C:\\Program Files\\eMudhra\\emudhra-pkcs11.dll"
                )
        );

        vendors.add(
                new Vendor(
                        "WatchData",
                        "C:\\Windows\\System32\\SignatureP11.dll"
                )
        );

        vendors.add(
                new Vendor(
                        "Feitian",
                        "C:\\Windows\\System32\\eps2003csp11.dll"
                )
        );

        return vendors;
    }

    public List<TokenInfo> scan() {
        List<TokenInfo> connectedTokens = new ArrayList<>();
        for (Vendor vendor : getSupportedVendors()) {

            System.out.println("\nScanning Vendor : " + vendor.getName());

            File dll = new File(vendor.getDllPath());

            if (!dll.exists()) {

                System.out.println("Library not found. Skipping...");
                continue;
            }

            try {

                TokenService tokenService =
                        new TokenService(vendor.getDllPath());

                tokenService.initialize();

                List<TokenInfo> tokens =
                        tokenService.getSlots();

                for (TokenInfo token : tokens) {

                    TokenInfo vendorToken =
                            new TokenInfo(
                                    vendor,
                                    token.getSlotId(),
                                    token.getLabel(),
                                    token.getManufacturer(),
                                    token.getModel(),
                                    token.getSerialNumber()
                            );

                    connectedTokens.add(vendorToken);
                }

                tokenService.finalizeLibrary();

            }
            catch (Exception ex) {

                System.out.println("Unable to scan vendor: "
                        + vendor.getName());

            }
        }
        return connectedTokens;
    }


}
