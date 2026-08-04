package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.service.KeyPairService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class KeyPairController {
    private final KeyPairService keyPairService;
    public KeyPairController(KeyPairService keyPairService)
    {
        this.keyPairService = keyPairService;
    }

    @GetMapping("/keypair")
    public String generateKeyPair() throws Exception{
        keyPairService.generateKeyPair();

        return "RSA 2048 Key pair Generated Succcessfully";
    }

}
