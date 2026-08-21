package in.cdac.pkcs11_library.service;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;

public class FindPrivateKey {

    public static PrivateKey findPrivateKey(
            Provider pkcs11Provider,
            byte[] ckaId,
            char[] pin) throws Exception {

        // Create PKCS#11 KeyStore
        KeyStore keyStore = KeyStore.getInstance("PKCS11", pkcs11Provider);

        // Login to token
        keyStore.load(null, pin);

        // Search through aliases
        var aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {

            String alias = aliases.nextElement();

            if (keyStore.isKeyEntry(alias)) {

                KeyStore.Entry entry =
                        keyStore.getEntry(alias, null);

                if (entry instanceof KeyStore.PrivateKeyEntry privateKeyEntry) {

                    PrivateKey privateKey = privateKeyEntry.getPrivateKey();

                    // Check whether this private key has the requested CKA_ID
                    // through the certificate/key association.
                    if (privateKeyEntry.getCertificate() != null) {
                        System.out.println("Found alias: " + alias);
                        return privateKey;
                    }
                }
            }
        }

        throw new RuntimeException("Private key not found");
    }
}
