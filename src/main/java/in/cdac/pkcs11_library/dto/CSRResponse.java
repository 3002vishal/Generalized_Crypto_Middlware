package in.cdac.pkcs11_library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CSRResponse {

    private String alias;
    private String csr;


}