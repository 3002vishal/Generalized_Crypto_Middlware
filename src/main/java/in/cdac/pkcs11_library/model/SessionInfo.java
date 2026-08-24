package in.cdac.pkcs11_library.model;

import in.cdac.pkcs11_library.pkcs11.PKCS11Manager;
import lombok.Data;

import java.security.KeyStore;
import java.security.Provider;

@Data
public class SessionInfo {

    private Provider provider;

    private KeyStore keyStore;

    private PKCS11Manager manager;


}
