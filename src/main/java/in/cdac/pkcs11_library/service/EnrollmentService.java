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

import java.security.*;

import java.security.cert.CertificateFactory;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
public class EnrollmentService {

    private final KeyPairService keyPairService;
    private final SessionService sessionService;
    private final RestClient restClient;


    // =====================================================
    // CONSTRUCTOR
    // =====================================================

    public EnrollmentService(
            KeyPairService keyPairService,
            SessionService sessionService) {

        this.keyPairService = keyPairService;
        this.sessionService = sessionService;

        this.restClient = RestClient.builder()
                .baseUrl("http://localhost:5000")
                .build();
    }


    // =====================================================
    // ENROLLMENT
    // =====================================================

    public String enroll(
            String alias,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            Map<String, String> serviceRoles,
            String pin) throws Exception {


        // =====================================================
        // 0. VALIDATE INPUT
        // =====================================================

        if (alias == null || alias.isBlank()) {
            throw new IllegalArgumentException(
                    "Alias is required."
            );
        }

        if (commonName == null || commonName.isBlank()) {
            throw new IllegalArgumentException(
                    "Common name is required."
            );
        }

        if (organization == null || organization.isBlank()) {
            throw new IllegalArgumentException(
                    "Organization is required."
            );
        }

        if (organizationalUnit == null ||
                organizationalUnit.isBlank()) {

            throw new IllegalArgumentException(
                    "Organizational unit is required."
            );
        }

        if (locality == null || locality.isBlank()) {
            throw new IllegalArgumentException(
                    "Locality is required."
            );
        }

        if (state == null || state.isBlank()) {
            throw new IllegalArgumentException(
                    "State is required."
            );
        }

        if (country == null || country.isBlank()) {
            throw new IllegalArgumentException(
                    "Country is required."
            );
        }

        if (pin == null || pin.isBlank()) {
            throw new IllegalArgumentException(
                    "Token PIN is required."
            );
        }

        if (serviceRoles == null) {
            throw new IllegalArgumentException(
                    "Service roles cannot be null."
            );
        }


        // =====================================================
        // 1. GET PKCS#11 KEYSTORE FROM CURRENT SESSION
        // =====================================================

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "STARTING CERTIFICATE ENROLLMENT"
        );

        System.out.println(
                "Alias: " + alias
        );

        System.out.println(
                "=============================================="
        );


        SessionInfo session =
                sessionService.getSession();


        if (session == null) {

            throw new IllegalStateException(
                    "No active PKCS#11 session. Please login first."
            );
        }


        KeyStore keyStore =
                session.getKeyStore();

        Provider pkcs11Provider = session.getProvider();

        if(pkcs11Provider == null)
        {
            throw new IllegalStateException("PKCS#11 Provider is not available");
        }


        if (keyStore == null) {

            throw new IllegalStateException(
                    "PKCS#11 KeyStore is not available."
            );
        }


        System.out.println(
                "PKCS#11 KeyStore obtained successfully."
        );


        // =====================================================
        // 2. PRINT SERVICE ROLES
        // =====================================================

        System.out.println(
                "=============================================="
        );

        System.out.println(
                "SERVICE ROLE MATRIX"
        );

        for (Map.Entry<String, String> entry :
                serviceRoles.entrySet()) {

            System.out.println(
                    "Service: " + entry.getKey() +
                            " | Role: " + entry.getValue()
            );
        }

        System.out.println(
                "=============================================="
        );


        // =====================================================
        // 3. GENERATE KEY PAIR ON TOKEN
        // =====================================================

        System.out.println(
                "1. Generating key pair..."
        );


        KeyPair keyPair =
                keyPairService.generateKeyPair(alias);


        if (keyPair == null) {

            throw new IllegalStateException(
                    "Key pair generation returned null."
            );
        }


        PrivateKey privateKey =
                keyPair.getPrivate();


        PublicKey publicKey =
                keyPair.getPublic();


        if (privateKey == null) {

            throw new IllegalStateException(
                    "Private key was not generated."
            );
        }


        if (publicKey == null) {

            throw new IllegalStateException(
                    "Public key was not generated."
            );
        }


        System.out.println(
                "Key pair generated on token."
        );

        System.out.println(
                "Public Key Algorithm: " +
                        publicKey.getAlgorithm()
        );

        System.out.println(
                "Private Key Algorithm: " +
                        privateKey.getAlgorithm()
        );


        // =====================================================
        // 4. BUILD CSR SUBJECT
        // =====================================================

        System.out.println(
                "2. Generating CSR..."
        );


        String dn = String.format(
                "CN=%s,O=%s,OU=%s,L=%s,ST=%s,C=%s",
                commonName.trim(),
                organization.trim(),
                organizationalUnit.trim(),
                locality.trim(),
                state.trim(),
                country.trim().toUpperCase()
        );


        System.out.println(
                "CSR Subject: " + dn
        );


        X500Name subject =
                new X500Name(dn);


        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        subject,
                        publicKey
                );


        // =====================================================
        // 5. SIGN CSR USING TOKEN PRIVATE KEY
        // =====================================================

        System.out.println(
                "3. Signing CSR using token private key..."
        );


        ContentSigner signer =
                new JcaContentSignerBuilder(
                        "SHA256withRSA"
                )
                        .setProvider(pkcs11Provider)
                        .build(privateKey);


        PKCS10CertificationRequest csr =
                csrBuilder.build(signer);


        System.out.println(
                "CSR signed successfully."
        );


        // =====================================================
        // 6. CONVERT CSR TO PEM
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


        System.out.println(
                "========== CSR =========="
        );

        System.out.println(csrPem);

        System.out.println(
                "========================="
        );


        // =====================================================
        // 7. SEND CSR + SERVICE ROLES TO NODE.JS CA
        // =====================================================

        System.out.println(
                "4. Sending CSR to CA..."
        );


        Map<String, Object> request =
                new HashMap<>();


        request.put(
                "username",
                alias.trim()
        );


        request.put(
                "csr",
                csrPem
        );


        // =====================================================
        // IMPORTANT
        // Send the COMPLETE service role map.
        //
        // Example:
        //
        // {
        //     "Crypto Vault": "NA",
        //     "dummy service ": "doaremon",
        //     "pki services": "NA",
        //     "Hsm Operation ": "c"
        // }
        // =====================================================

        request.put(
                "serviceRoles",
                serviceRoles
        );


        System.out.println(
                "Sending service role matrix to CA:"
        );

        System.out.println(
                serviceRoles
        );


        // =====================================================
        // 8. CALL NODE.JS CA
        // =====================================================

        Map response;

        try {

            response =
                    restClient.post()
                            .uri("/api/enroll")
                            .body(request)
                            .retrieve()
                            .body(Map.class);

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to communicate with CA: " +
                            e.getMessage(),
                    e
            );
        }


        // =====================================================
        // 9. VALIDATE CA RESPONSE
        // =====================================================

        if (response == null) {

            throw new IllegalStateException(
                    "CA returned empty response."
            );
        }


        System.out.println(
                "========== CA RESPONSE =========="
        );

        System.out.println(
                response
        );

        System.out.println(
                "================================="
        );


        Object successObject =
                response.get("success");


        boolean success =
                Boolean.TRUE.equals(successObject);


        if (!success) {

            Object error =
                    response.get("error");

            Object message =
                    response.get("message");


            String errorMessage =
                    error != null
                            ? error.toString()
                            : message != null
                              ? message.toString()
                              : response.toString();


            throw new IllegalStateException(
                    "CA enrollment failed: " +
                            errorMessage
            );
        }


        // =====================================================
        // 10. GET CERTIFICATE FROM CA RESPONSE
        // =====================================================

        Object certificateObject =
                response.get("certificate");


        if (certificateObject == null) {

            throw new IllegalStateException(
                    "CA returned no certificate."
            );
        }


        String certificatePem =
                certificateObject.toString();


        if (certificatePem.isBlank()) {

            throw new IllegalStateException(
                    "CA returned an empty certificate."
            );
        }


        System.out.println(
                "Certificate received from CA."
        );


        System.out.println(
                "========== CERTIFICATE RESPONSE =========="
        );

        System.out.println(
                certificatePem
        );

        System.out.println(
                "=========================================="
        );


        // =====================================================
        // 11. PARSE CERTIFICATE
        // =====================================================

        System.out.println(
                "5. Parsing certificate..."
        );


        CertificateFactory certificateFactory =
                CertificateFactory.getInstance("X.509");


        String cleanedCertificate =
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


        byte[] certificateBytes;


        try {

            certificateBytes =
                    Base64.getDecoder()
                            .decode(cleanedCertificate);

        } catch (IllegalArgumentException e) {

            throw new IllegalStateException(
                    "CA returned an invalid Base64 certificate.",
                    e
            );
        }


        java.security.cert.Certificate certificate =
                certificateFactory.generateCertificate(
                        new ByteArrayInputStream(
                                certificateBytes
                        )
                );


        if (certificate == null) {

            throw new IllegalStateException(
                    "Unable to parse X.509 certificate."
            );
        }


        System.out.println(
                "Certificate parsed successfully."
        );


        // =====================================================
        // 12. VERIFY CERTIFICATE PUBLIC KEY
        // =====================================================

        System.out.println(
                "6. Verifying certificate public key..."
        );


        PublicKey certificatePublicKey =
                certificate.getPublicKey();


        if (certificatePublicKey == null) {

            throw new SecurityException(
                    "Certificate does not contain a public key."
            );
        }


        if (!certificatePublicKey.equals(publicKey)) {

            throw new SecurityException(
                    "Certificate public key does not match " +
                            "the generated token key pair!"
            );
        }


        System.out.println(
                "Certificate public key matches key pair."
        );


        // =====================================================
        // 13. CREATE CERTIFICATE CHAIN
        // =====================================================

        System.out.println(
                "7. Creating certificate chain..."
        );


        java.security.cert.Certificate[] chain =
                new java.security.cert.Certificate[]{
                        certificate
                };


        // =====================================================
        // 14. MAP CERTIFICATE TO PRIVATE KEY
        // =====================================================

        System.out.println(
                "8. Mapping certificate to private key..."
        );


        /*
         * This associates the certificate chain with
         * the private key under the supplied alias.
         */

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
        // 15. VERIFY KEYSTORE ENTRY
        // =====================================================

        System.out.println(
                "9. Verifying KeyStore entry..."
        );


        KeyStore.Entry entry;


        try {

            entry =
                    keyStore.getEntry(
                            alias,
                            new KeyStore.PasswordProtection(
                                    pin.toCharArray()
                            )
                    );

        } catch (Exception e) {

            throw new IllegalStateException(
                    "Unable to retrieve KeyStore entry for alias: " +
                            alias,
                    e
            );
        }


        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {

            throw new IllegalStateException(
                    "Certificate was not associated " +
                            "with the private key for alias: " +
                            alias
            );
        }


        KeyStore.PrivateKeyEntry privateKeyEntry =
                (KeyStore.PrivateKeyEntry) entry;


        // =====================================================
        // 16. ADDITIONAL PUBLIC KEY VERIFICATION
        // =====================================================

        java.security.cert.Certificate storedCertificate =
                privateKeyEntry.getCertificate();


        if (storedCertificate == null) {

            throw new IllegalStateException(
                    "KeyStore entry contains no certificate."
            );
        }


        if (!storedCertificate
                .getPublicKey()
                .equals(publicKey)) {

            throw new SecurityException(
                    "Stored certificate public key does not " +
                            "match the generated token public key."
            );
        }


        // =====================================================
        // 17. SUCCESS
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
                "Service Roles: " + serviceRoles
        );

        System.out.println(
                "Certificate successfully associated " +
                        "with the private key."
        );

        System.out.println(
                "===================================="
        );


        return certificatePem;
    }
}