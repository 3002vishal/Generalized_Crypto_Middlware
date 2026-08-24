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

    public KeyPair generateKeyPair(String alias) throws Exception {

        // Get the provider created during login
        Provider provider =
                sessionService.getSession().getProvider();

        if (provider == null) {
            throw new IllegalStateException(
                    "PKCS#11 provider not available. Login first."
            );
        }

        System.out.println("--------------------------------");
        System.out.println("USING PKCS#11 PROVIDER");
        System.out.println("--------------------------------");
        System.out.println(
                "Provider : " + provider.getName()
        );

        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(
                        "RSA",
                        provider
                );

        keyPairGenerator.initialize(2048);

        KeyPair keyPair =
                keyPairGenerator.generateKeyPair();

        System.out.println("--------------------------------");
        System.out.println("KEY PAIR GENERATED");
        System.out.println("--------------------------------");
        System.out.println("Alias : " + alias);

        return keyPair;
    }
}