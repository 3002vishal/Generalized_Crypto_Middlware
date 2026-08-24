package in.cdac.pkcs11_library.service;


@Service
public class EnrollmentService {

    private final KeyPairService keyPairService;
    private final KeyStore keyStore;
    private final RestClient restClient;

    public EnrollmentService(
            KeyPairService keyPairService,
            KeyStore keyStore) {

        this.keyPairService = keyPairService;
        this.keyStore = keyStore;

        this.restClient = RestClient.builder()
                .baseUrl("http://localhost:3000")
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
        // 1. GENERATE KEY PAIR ON TOKEN
        // =====================================================

        System.out.println("1. Generating key pair...");

        KeyPair keyPair =
                keyPairService.generateKeyPair(alias);

        PrivateKey privateKey =
                keyPair.getPrivate();

        PublicKey publicKey =
                keyPair.getPublic();


        // =====================================================
        // 2. BUILD CSR
        // =====================================================

        System.out.println("2. Generating CSR...");

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

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .build(privateKey);

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


        System.out.println("CSR generated.");


        // =====================================================
        // 5. SEND CSR TO NODE.JS CA
        // =====================================================

        System.out.println("3. Sending CSR to CA...");

        Map<String, Object> request =
                new HashMap<>();

        request.put("username", alias);
        request.put("csr", csrPem);
        request.put("serviceRoles", serviceRoles);


        Map response =
                restClient.post()
                        .uri("/enroll")
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
                        .replaceAll("\\s+", "");

        byte[] certificateBytes =
                Base64.getDecoder()
                        .decode(cleaned);

        Certificate certificate =
                certificateFactory.generateCertificate(
                        new ByteArrayInputStream(
                                certificateBytes
                        )
                );


        // =====================================================
        // 7. VERIFY THAT CERTIFICATE MATCHES PUBLIC KEY
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
                "Mapping certificate to private key..."
        );

        Certificate[] chain =
                new Certificate[]{
                        certificate
                };


        keyStore.setKeyEntry(
                alias,
                privateKey,
                pin.toCharArray(),
                chain
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
