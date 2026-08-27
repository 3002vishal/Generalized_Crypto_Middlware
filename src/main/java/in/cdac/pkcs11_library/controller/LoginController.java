package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.dto.LoginRequest;
import in.cdac.pkcs11_library.service.LoginService;
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
public class LoginController {

    private final LoginService loginService;

    public LoginController(LoginService loginService) {
        this.loginService = loginService;
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request)
            throws Exception {

        loginService.login(request);

        return "Login Successful";
    }

}
