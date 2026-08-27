package in.cdac.pkcs11_library.dto;

import lombok.Data;

import java.util.Map;

@Data
public class EnrollmentRequest {

    private String alias;
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String locality;
    private String state;
    private String country;
    private Map<String , String> serviceRoles;
    private String pin;

    // getters and setters
}
