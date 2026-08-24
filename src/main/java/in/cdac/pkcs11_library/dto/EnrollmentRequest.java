package in.cdac.pkcs11_library.dto;

import lombok.Data;

@Data
public class EnrollmentRequest {

    private String alias;
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String locality;
    private String state;
    private String country;
    private String serviceRoles;
    private String pin;

    // getters and setters
}
