package in.cdac.pkcs11_library.service;

import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;

@Service
public class KeyPairService {

    private final SessionService sessionService;

    public KeyPairService(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public KeyPair generateKeyPair() throws Exception {

        // Check whether user is logged into the token
        if (!sessionService.isLoggedIn()) {
            throw new RuntimeException("No active Session");
        }

        // Get the PKCS#11 provider
        Provider provider = sessionService.getSession().getProvider();

        // Get RSA KeyPairGenerator from the PKCS#11 provider
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA", provider);

        // Generate a new 2048-bit RSA key pair
        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        System.out.println("--------------------------------");
        System.out.println("New RSA 2048 Key Pair Generated");
        System.out.println("--------------------------------");

        return keyPair;
    }
}