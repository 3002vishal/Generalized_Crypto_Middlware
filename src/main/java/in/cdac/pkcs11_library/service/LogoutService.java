package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.model.SessionInfo;
import in.cdac.pkcs11_library.pkcs11.PKCS11Manager;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;

@Service
public class LogoutService {

    private final SessionService sessionService;

    public LogoutService(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public void logout() {

        SessionInfo session = sessionService.getSession();

        if (session == null) {
            System.out.println("No active PKCS#11 session.");
            return;
        }

        Provider provider = session.getProvider();
        PKCS11Manager manager = session.getManager();

        try {

            // =====================================================
            // 1. Logout from the PKCS#11 token
            // =====================================================

            if (manager != null) {

                manager.logout();

                System.out.println(
                        "Token logout successful"
                );
            }

        } catch (Exception e) {

            System.err.println(
                    "Token logout failed: "
                            + e.getMessage()
            );

        } finally {

            // =====================================================
            // 2. Remove provider from JVM
            // =====================================================

            if (provider != null) {

                String providerName = provider.getName();

                Security.removeProvider(providerName);

                System.out.println(
                        "Provider removed: " + providerName
                );
            }

            // =====================================================
            // 3. Delete temporary configuration file
            // =====================================================

            if (session.getConfigFilePath() != null) {

                try {

                    Files.deleteIfExists(
                            Path.of(session.getConfigFilePath())
                    );

                    System.out.println(
                            "Temporary PKCS#11 config deleted"
                    );

                } catch (Exception e) {

                    System.err.println(
                            "Could not delete config file: "
                                    + e.getMessage()
                    );
                }
            }

            // =====================================================
            // 4. Clear application session
            // =====================================================

            sessionService.clearSession();

            System.out.println(
                    "Application PKCS#11 session cleared"
            );
        }
    }
}