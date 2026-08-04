package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.dto.LoginRequest;
import in.cdac.pkcs11_library.service.LoginService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
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
