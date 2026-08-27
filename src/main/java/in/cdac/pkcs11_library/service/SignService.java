package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.model.SessionInfo;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Base64;

@Service
public class SignService {

    private final SessionService sessionService;

    public SignService(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public String signChallenge(
            String alias,
            String challenge
    ) throws Exception {

        // =====================================================
        // 1. GET CURRENT PKCS#11 SESSION
        // =====================================================

        SessionInfo session =
                sessionService.getSession();

        if (session == null) {
            throw new IllegalStateException(
                    "No active PKCS#11 session. Please login first."
            );
        }

        // =====================================================
        // 2. GET PKCS#11 KEYSTORE
        // =====================================================

        KeyStore keyStore =
                session.getKeyStore();

        if (keyStore == null) {
            throw new IllegalStateException(
                    "PKCS#11 KeyStore unavailable."
            );
        }

        System.out.println(
                "PKCS#11 KeyStore obtained successfully."
        );

        // =====================================================
        // 3. CHECK ALIAS
        // =====================================================

        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException(
                    "Alias cannot be empty."
            );
        }

        System.out.println(
                "Requested alias: " + alias
        );

        if (!keyStore.containsAlias(alias)) {
            throw new IllegalArgumentException(
                    "Alias not found on token: " + alias
            );
        }

        // =====================================================
        // 4. GET PRIVATE KEY ENTRY
        // =====================================================

        KeyStore.Entry entry =
                keyStore.getEntry(
                        alias,
                        null
                );

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new IllegalStateException(
                    "Alias does not contain a private key: "
                            + alias
            );
        }

        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) entry;

        PrivateKey privateKey =
                privateKeyEntry.getPrivateKey();

        System.out.println(
                "Private key obtained successfully."
        );

        System.out.println(
                "Private key class: "
                        + privateKey.getClass().getName()
        );

        // =====================================================
        // 5. GET PKCS#11 PROVIDER
        // =====================================================

        Provider pkcs11Provider =
                keyStore.getProvider();

        if (pkcs11Provider == null) {
            throw new IllegalStateException(
                    "PKCS#11 provider is unavailable."
            );
        }

        System.out.println(
                "PKCS#11 Provider: "
                        + pkcs11Provider.getName()
        );

        // =====================================================
        // 6. CHECK CHALLENGE
        // =====================================================

        if (challenge == null || challenge.isBlank()) {
            throw new IllegalArgumentException(
                    "Challenge cannot be empty."
            );
        }

        System.out.println(
                "Challenge received: " + challenge
        );

        // =====================================================
        // 7. CREATE SIGNATURE USING PKCS#11 PROVIDER
        // =====================================================

        Signature signature =
                Signature.getInstance(
                        "SHA256withRSA",
                        pkcs11Provider
                );

        // This causes the signing operation to use
        // the private key inside the PKCS#11 token.
        signature.initSign(privateKey);

        System.out.println(
                "Signature initialized successfully."
        );

        // =====================================================
        // 8. SIGN CHALLENGE
        // =====================================================

        byte[] challengeBytes =
                challenge.getBytes(
                        StandardCharsets.UTF_8
                );

        signature.update(challengeBytes);

        byte[] signedChallenge =
                signature.sign();

        System.out.println(
                "Challenge signed successfully."
        );

        // =====================================================
        // 9. CONVERT SIGNATURE TO BASE64
        // =====================================================

        String signatureBase64 =
                Base64.getEncoder()
                        .encodeToString(
                                signedChallenge
                        );

        System.out.println(
                "Signature generated successfully."
        );

        // =====================================================
        // 10. RETURN SIGNATURE
        // =====================================================

        return signatureBase64;
    }
}