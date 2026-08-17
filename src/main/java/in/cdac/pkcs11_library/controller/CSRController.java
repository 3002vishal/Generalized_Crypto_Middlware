package in.cdac.pkcs11_library.controller;

import in.cdac.pkcs11_library.dto.CSRequest;
import in.cdac.pkcs11_library.service.CSRService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("csr")
public class CSRController {

    private final CSRService csrService;

    public CSRController(CSRService csrService)
    {
        this.csrService = csrService;
    }

    @PostMapping("/generate")
    public ResponseEntity<String> generateCSR(
            @RequestBody CSRequest request
            ) throws Exception{
        String csr = csrService.generateCSR(
                request.getCommonName(),
                request.getOrganization(),
                request.getOrganizationalUnit(),
                request.getLocality(),
                request.getState(),
                request.getCountry()
        );
        return ResponseEntity.ok(csr);
    }


}
