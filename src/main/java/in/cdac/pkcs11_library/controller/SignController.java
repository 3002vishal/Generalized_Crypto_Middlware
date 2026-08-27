package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.service.SignService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

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
public class SignController {

    private final SignService signService;

    public SignController(SignService signService) {
        this.signService = signService;
    }

    @PostMapping("/sign-challenge")
    public ResponseEntity<?> signChallenge(
            @RequestParam String alias,
            @RequestParam String challenge
    ) {

        try {

            String signature =
                    signService.signChallenge(
                            alias,
                            challenge
                    );

            return ResponseEntity.ok(
                    Map.of(
                            "success", true,
                            "alias", alias,
                            "challenge", challenge,
                            "signature", signature
                    )
            );

        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .badRequest()
                    .body(
                            Map.of(
                                    "success", false,
                                    "error", e.getMessage()
                            )
                    );
        }
    }
}
