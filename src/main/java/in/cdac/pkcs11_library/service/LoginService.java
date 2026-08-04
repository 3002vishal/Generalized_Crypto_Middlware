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

        try {

            // Create PKCS#11 configuration file
            Path configFile = createConfigFile(
                    request.getDllPath(),
                    request.getSlotId()
            );

            // Configure SunPKCS11 Provider
            Provider provider = Security.getProvider("SunPKCS11");

            provider = provider.configure(configFile.toString());

            Security.addProvider(provider);

            // Login to token
            PKCS11Manager manager = new PKCS11Manager(provider);

            manager.login(request.getPin().toCharArray());

            // Store session
            SessionInfo sessionInfo = new SessionInfo();

            sessionInfo.setProvider(provider);
            sessionInfo.setManager(manager);

            sessionService.setSession(sessionInfo);

            System.out.println("Login Successful");

        }
        catch (Exception e) {
            throw new RuntimeException("Login failed.", e);
        }
    }

    private Path createConfigFile(String dllPath, long slotId) throws Exception {

        InputStream inputStream =
                getClass().getResourceAsStream("/pkcs11.cfg");

        if (inputStream == null) {
            throw new RuntimeException("pkcs11.cfg not found.");
        }

        String config = new String(
                inputStream.readAllBytes(),
                StandardCharsets.UTF_8
        );

        inputStream.close();

        config = config.replace("${LIBRARY}", dllPath);

        config = config.replace(
                "${SLOT}",
                String.valueOf(slotId)
        );

        Path configFile =
                Files.createTempFile("pkcs11-", ".cfg");

        Files.writeString(configFile, config);

        return configFile;
    }
}