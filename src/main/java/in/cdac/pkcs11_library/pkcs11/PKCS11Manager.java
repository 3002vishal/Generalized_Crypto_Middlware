package in.cdac.pkcs11_library.pkcs11;

import lombok.AllArgsConstructor;

import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

@AllArgsConstructor
public class PKCS11Manager {

    private final Provider provider;

    private KeyStore keyStore;

    public PKCS11Manager(Provider provider) {
        this.provider = provider;
    }

    public Provider getProvider() {
        return provider;
    }

    public void login(char[] pin) throws Exception {

        keyStore = KeyStore.getInstance(
                "PKCS11",
                provider
        );

        keyStore.load(null, pin);

        System.out.println("Login Successful");

        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            System.out.println("Alias : " + aliases.nextElement());
        }
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public X509Certificate getCertificate(String alias) throws Exception {
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    public PrivateKey getPrivateKey(
            String alias,
            char[] pin
    ) throws Exception {

        return (PrivateKey) keyStore.getKey(alias, pin);
    }

    /**
     * Logout from the PKCS#11 token.
     */
    public void logout() {

        try {

            if (provider instanceof AuthProvider authProvider) {

                authProvider.logout();

                System.out.println(
                        "PKCS#11 provider logout successful"
                );
            }

        } catch (Exception e) {

            System.err.println(
                    "Error while logging out from PKCS#11 provider: "
                            + e.getMessage()
            );
        }

        keyStore = null;
    }
}