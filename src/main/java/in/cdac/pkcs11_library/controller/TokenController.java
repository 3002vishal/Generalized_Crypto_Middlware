package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.model.TokenInfo;
import in.cdac.pkcs11_library.service.TokenService;
import in.cdac.pkcs11_library.service.VendorScannerService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping
@CrossOrigin(origins = "*" )
public class TokenController
{
    private final VendorScannerService vendorScannerService;

    public TokenController(VendorScannerService vendorScannerService)
    {
        this.vendorScannerService = vendorScannerService;
    }
    @GetMapping("/tokens")
    public List<TokenInfo> getTokens(){
        return vendorScannerService.scan();
    }


}
