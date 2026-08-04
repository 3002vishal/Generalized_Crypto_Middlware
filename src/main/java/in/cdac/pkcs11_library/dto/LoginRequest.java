package in.cdac.pkcs11_library.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private long slotId;
    private String pin;
    private String dllPath;
}
