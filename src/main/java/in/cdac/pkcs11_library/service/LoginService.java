package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.dto.LoginRequest;
import in.cdac.pkcs11_library.model.SessionInfo;
import in.cdac.pkcs11_library.pkcs11.PKCS11Manager;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

@Service
public class LoginService {

    private final SessionService sessionService;

    public LoginService(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public void login(LoginRequest request) {

        Path configFile = null;

        try {

            // =====================================================
            // 1. Create PKCS#11 configuration
            // =====================================================

            configFile = createConfigFile(
                    request.getDllPath(),
                    request.getSlotId()
            );

            // =====================================================
            // 2. Get base SunPKCS11 provider
            // =====================================================

            Provider baseProvider =
                    Security.getProvider("SunPKCS11");

            if (baseProvider == null) {

                throw new RuntimeException(
                        "SunPKCS11 provider not available"
                );
            }

            // =====================================================
            // 3. Configure provider
            // =====================================================

            Provider provider =
                    baseProvider.configure(
                            configFile.toString()
                    );

            Security.addProvider(provider);

            // =====================================================
            // 4. Create manager
            // =====================================================

            PKCS11Manager manager =
                    new PKCS11Manager(provider);

            // =====================================================
            // 5. Login
            // =====================================================

            manager.login(
                    request.getPin().toCharArray()
            );

            // =====================================================
            // 6. Create session
            // =====================================================

            SessionInfo sessionInfo =
                    new SessionInfo();

            sessionInfo.setProvider(provider);
            sessionInfo.setManager(manager);
            sessionInfo.setKeyStore(
                    manager.getKeyStore()
            );
            sessionInfo.setConfigFilePath(
                    configFile.toString()
            );

            sessionService.setSession(sessionInfo);

            System.out.println(
                    "PKCS#11 Login Successful"
            );

        } catch (Exception e) {

            // If login failed, clean up the provider/config
            if (configFile != null) {

                try {
                    Files.deleteIfExists(configFile);
                } catch (Exception ignored) {
                }
            }

            throw new RuntimeException(
                    "Login failed.",
                    e
            );
        }
    }

    private Path createConfigFile(
            String dllPath,
            long slotId
    ) throws Exception {

        InputStream inputStream =
                getClass()
                        .getResourceAsStream("/pkcs11.cfg");

        if (inputStream == null) {

            throw new RuntimeException(
                    "pkcs11.cfg not found."
            );
        }

        String config;

        try (inputStream) {

            config = new String(
                    inputStream.readAllBytes(),
                    StandardCharsets.UTF_8
            );
        }

        config = config.replace(
                "${LIBRARY}",
                dllPath
        );

        config = config.replace(
                "${SLOT}",
                String.valueOf(slotId)
        );

        Path configFile =
                Files.createTempFile(
                        "pkcs11-",
                        ".cfg"
                );

        Files.writeString(
                configFile,
                config
        );

        return configFile;
    }
}