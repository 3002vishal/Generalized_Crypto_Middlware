package in.cdac.pkcs11_library.dto;

import lombok.Data;

@Data
public class CSRequest
{
    private String alias;
    private String commonName;
    private String organization;
    private String OrganizationalUnit;
    private String locality;
    private String state;
    private String country;
}
