package in.cdac.pkcs11_library.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;

import java.io.StringWriter;
import java.security.KeyPair;

@Service
public class CSRService {

    private final KeyPairService keyPairService;

    public CSRService(KeyPairService keyPairService) {
        this.keyPairService = keyPairService;
    }

    public String generateCSR(
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country) throws Exception {

        // =====================================================
        // 1. Generate NEW key pair on the crypto token
        // =====================================================

        KeyPair keyPair = keyPairService.generateKeyPair();


        // =====================================================
        // 2. Build Subject DN
        // =====================================================

        String dn = String.format(
                "CN=%s,O=%s,OU=%s,L=%s,ST=%s,C=%s",
                commonName,
                organization,
                organizationalUnit,
                locality,
                state,
                country
        );

        X500Name subject = new X500Name(dn);


        // =====================================================
        // 3. Create CSR builder using PUBLIC key
        // =====================================================

        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        subject,
                        keyPair.getPublic()
                );


        // =====================================================
        // 4. Create signer using PRIVATE key
        //
        // Private key remains inside the crypto token.
        // =====================================================

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());


        // =====================================================
        // 5. Generate CSR
        // =====================================================

        PKCS10CertificationRequest csr =
                csrBuilder.build(signer);


        // =====================================================
        // 6. Convert CSR to PEM
        // =====================================================

        StringWriter stringWriter = new StringWriter();

        try (JcaPEMWriter pemWriter =
                     new JcaPEMWriter(stringWriter)) {

            pemWriter.writeObject(csr);
        }

        String pemCSR = stringWriter.toString();

        System.out.println("--------------------------------");
        System.out.println("CSR Generated Successfully");
        System.out.println("--------------------------------");

        return pemCSR;
    }
}