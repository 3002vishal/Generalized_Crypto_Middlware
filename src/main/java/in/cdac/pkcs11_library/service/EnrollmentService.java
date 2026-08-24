package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.model.SessionInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.Certificate;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class EnrollmentService {

    private final KeyPairService keyPairService;
    private final SessionService sessionService;
    private final RestClient restClient;

    public EnrollmentService(
            KeyPairService keyPairService,
            SessionService sessionService) {

        this.keyPairService = keyPairService;
        this.sessionService = sessionService;

        this.restClient = RestClient.builder()
                .baseUrl("http://localhost:5000")
                .build();
    }

    public String enroll(
            String alias,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            String serviceRoles,
            String pin) throws Exception {

        // =====================================================
        // 0. GET PKCS#11 KEYSTORE FROM CURRENT SESSION
        // =====================================================

        SessionInfo session =
                sessionService.getSession();

        if (session == null) {
            throw new IllegalStateException(
                    "No active PKCS#11 session. Please login first."
            );
        }

        KeyStore keyStore =
                session.getKeyStore();

        if (keyStore == null) {
            throw new IllegalStateException(
                    "PKCS#11 KeyStore is not available."
            );
        }

        System.out.println(
                "PKCS#11 KeyStore obtained successfully."
        );


        // =====================================================
        // 1. GENERATE KEY PAIR ON TOKEN
        // =====================================================

        System.out.println(
                "1. Generating key pair..."
        );

        KeyPair keyPair =
                keyPairService.generateKeyPair(alias);

        PrivateKey privateKey =
                keyPair.getPrivate();

        PublicKey publicKey =
                keyPair.getPublic();

        System.out.println(
                "Key pair generated on token."
        );


        // =====================================================
        // 2. BUILD CSR
        // =====================================================

        System.out.println(
                "2. Generating CSR..."
        );

        String dn = String.format(
                "CN=%s,O=%s,OU=%s,L=%s,ST=%s,C=%s",
                commonName,
                organization,
                organizationalUnit,
                locality,
                state,
                country
        );

        X500Name subject =
                new X500Name(dn);

        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        subject,
                        publicKey
                );


        // =====================================================
        // 3. SIGN CSR USING TOKEN PRIVATE KEY
        // =====================================================

        System.out.println(
                "3. Signing CSR using token private key..."
        );

        ContentSigner signer =
                new JcaContentSignerBuilder(
                        "SHA256withRSA"
                ).build(privateKey);

        PKCS10CertificationRequest csr =
                csrBuilder.build(signer);


        // =====================================================
        // 4. CONVERT CSR TO PEM
        // =====================================================

        StringWriter writer =
                new StringWriter();

        try (JcaPEMWriter pemWriter =
                     new JcaPEMWriter(writer)) {

            pemWriter.writeObject(csr);
        }

        String csrPem =
                writer.toString();

        System.out.println(
                "CSR generated successfully."
        );


        // =====================================================
        // 5. SEND CSR TO NODE.JS CA
        // =====================================================

        System.out.println(
                "4. Sending CSR to CA..."
        );

        Map<String, Object> request =
                new HashMap<>();

        request.put(
                "username",
                alias
        );

        request.put(
                "csr",
                csrPem
        );

        request.put(
                "serviceRoles",
                serviceRoles
        );

        Map response =
                restClient.post()
                        .uri("/api/enroll")
                        .body(request)
                        .retrieve()
                        .body(Map.class);

        if (response == null) {
            throw new IllegalStateException(
                    "CA returned empty response"
            );
        }

        Boolean success =
                (Boolean) response.get("success");

        if (!Boolean.TRUE.equals(success)) {
            throw new IllegalStateException(
                    "CA enrollment failed: " + response
            );
        }

        String certificatePem =
                (String) response.get("certificate");

        if (certificatePem == null ||
                certificatePem.isBlank()) {

            throw new IllegalStateException(
                    "CA returned no certificate"
            );
        }

        System.out.println(
                "Certificate received from CA."
        );
        System.out.println("========== CERTIFICATE RESPONSE ==========");
        System.out.println(certificatePem);
        System.out.println("==========================================");




        // =====================================================
        // 6. PARSE CERTIFICATE
        // =====================================================

        CertificateFactory certificateFactory =
                CertificateFactory.getInstance("X.509");

        String cleaned =
                certificatePem
                        .replace(
                                "-----BEGIN CERTIFICATE-----",
                                ""
                        )
                        .replace(
                                "-----END CERTIFICATE-----",
                                ""
                        )
                        .replaceAll(
                                "\\s+",
                                ""
                        );

        byte[] certificateBytes =
                Base64.getDecoder()
                        .decode(cleaned);

        java.security.cert.Certificate certificate =
                certificateFactory.generateCertificate(
                        new ByteArrayInputStream(
                                certificateBytes
                        )
                );


        // =====================================================
        // 7. VERIFY CERTIFICATE MATCHES PUBLIC KEY
        // =====================================================

        PublicKey certificatePublicKey =
                certificate.getPublicKey();

        if (!certificatePublicKey.equals(publicKey)) {

            throw new SecurityException(
                    "Certificate public key does not match " +
                            "the generated key pair!"
            );
        }

        System.out.println(
                "Certificate public key matches key pair."
        );


        // =====================================================
        // 8. MAP CERTIFICATE TO PRIVATE KEY
        // =====================================================

        System.out.println(
                "8. Mapping certificate to private key..."
        );

        java.security.cert.Certificate[] chain =
                new java.security.cert.Certificate[]{
                        certificate
                };


        // =====================================================
        // THIS IS THE CODE YOU WANT
        // =====================================================

        keyStore.setKeyEntry(
                alias,
                privateKey,
                pin.toCharArray(),
                chain
        );

        System.out.println(
                "Certificate mapped to private key."
        );


        // =====================================================
        // 9. VERIFY KEYSTORE ENTRY
        // =====================================================

        KeyStore.Entry entry =
                keyStore.getEntry(
                        alias,
                        new KeyStore.PasswordProtection(
                                pin.toCharArray()
                        )
                );

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {

            throw new IllegalStateException(
                    "Certificate was not associated " +
                            "with private key"
            );
        }

        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) entry;


        // =====================================================
        // 10. SUCCESS
        // =====================================================

        System.out.println(
                "===================================="
        );

        System.out.println(
                "ENROLLMENT SUCCESSFUL"
        );

        System.out.println(
                "Alias: " + alias
        );

        System.out.println(
                "Certificate: " +
                        privateKeyEntry.getCertificate()
        );

        System.out.println(
                "===================================="
        );

        return certificatePem;
    }
}