package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.dto.CSRequest;
import in.cdac.pkcs11_library.dto.CSRResponse;
import in.cdac.pkcs11_library.service.CSRService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/csr")
public class CSRController {

    private final CSRService csrService;

    public CSRController(CSRService csrService) {
        this.csrService = csrService;
    }

    @PostMapping("/generate")
    public ResponseEntity<CSRResponse> generateCSR(
            @RequestBody CSRequest request) throws Exception {

        CSRResponse response =
                csrService.generateCSR(
                        request.getAlias(),
                        request.getCommonName(),
                        request.getOrganization(),
                        request.getOrganizationalUnit(),
                        request.getLocality(),
                        request.getState(),
                        request.getCountry()
                );

        return ResponseEntity.ok(response);
    }
}