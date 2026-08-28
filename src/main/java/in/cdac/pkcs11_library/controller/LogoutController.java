package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.service.LogoutService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@CrossOrigin(
        origins = {
                "http://localhost:3000",
                "http://localhost:5000"
        },
        allowedHeaders = "*",
        methods = {
                RequestMethod.POST,
                RequestMethod.OPTIONS
        }
)
public class LogoutController {

    private final LogoutService logoutService;

    public LogoutController(LogoutService logoutService) {
        this.logoutService = logoutService;
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {

        logoutService.logout();

        return ResponseEntity.ok(
                "PKCS#11 token logged out successfully"
        );
    }
}