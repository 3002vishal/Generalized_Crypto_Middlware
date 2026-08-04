package in.cdac.pkcs11_library.service;


import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;

import java.io.FileWriter;
import java.security.KeyPair;

@Service
public class CSRService {

    public void generateCSR(
            KeyPair keyPair,
            String commonName,
            String organization,
            String organizationalUnit,
            String locality,
            String state,
            String country,
            String outputFile) throws Exception {

        // Build Subject DN
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

        // Build CSR
        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(
                        subject,
                        keyPair.getPublic()
                );

        // Create signer using the private key stored in the token
        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());

        // Generate CSR
        PKCS10CertificationRequest csr =
                csrBuilder.build(signer);

        // Save CSR as PEM
        try (JcaPEMWriter writer =
                     new JcaPEMWriter(new FileWriter(outputFile))) {

            writer.writeObject(csr);
        }

        System.out.println("--------------------------------");
        System.out.println("CSR Generated Successfully");
        System.out.println("Saved to : " + outputFile);
        System.out.println("--------------------------------");
    }
}

