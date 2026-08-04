package in.cdac.pkcs11_library.service;

import in.cdac.pkcs11_library.model.SessionInfo;
import lombok.Data;
import org.springframework.stereotype.Service;

@Data
@Service
public class SessionService {

    private SessionInfo session;

    public boolean isLoggedIn()
    {
        return session != null;
    }

    public void clearSession()
    {
        session = null;
    }

}
