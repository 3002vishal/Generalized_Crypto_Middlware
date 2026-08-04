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

    public void generateKeyPair() throws Exception {
        if (!sessionService.isLoggedIn()) {
            throw new RuntimeException("No active Session");
        }

        Provider provider = sessionService.getSession().getProvider();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);

        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        System.out.println("RSA 2048 key Pair Generated Successfully");


    }
}
