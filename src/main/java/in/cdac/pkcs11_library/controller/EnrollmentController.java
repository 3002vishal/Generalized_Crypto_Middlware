package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.dto.EnrollmentRequest;
import in.cdac.pkcs11_library.service.EnrollmentService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/enrollment")
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
public class EnrollmentController {

    private final EnrollmentService enrollmentService;

    public EnrollmentController(
            EnrollmentService enrollmentService) {
        this.enrollmentService = enrollmentService;
    }

    @PostMapping("/enroll")
    public ResponseEntity<?> enroll(
            @RequestBody EnrollmentRequest request) {

        try {

            String certificate =
                    enrollmentService.enroll(
                            request.getAlias(),
                            request.getCommonName(),
                            request.getOrganization(),
                            request.getOrganizationalUnit(),
                            request.getLocality(),
                            request.getState(),
                            request.getCountry(),
                            request.getServiceRoles(),
                            request.getPin()
                    );

            return ResponseEntity.ok(
                    Map.of(
                            "success", true,
                            "alias", request.getAlias(),
                            "certificate", certificate
                    )
            );

        } catch (Exception e) {

            e.printStackTrace();

            return ResponseEntity
                    .internalServerError()
                    .body(
                            Map.of(
                                    "success", false,
                                    "error",
                                    e.getMessage() != null
                                            ? e.getMessage()
                                            : "Certificate enrollment failed"
                            )
                    );
        }
    }
}