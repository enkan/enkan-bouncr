package enkan.security.bouncr;

import com.fasterxml.jackson.core.type.TypeReference;
import enkan.data.HttpRequest;
import enkan.security.AuthBackend;
import net.unit8.bouncr.sign.JsonWebToken;

import javax.inject.Inject;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.*;

import static enkan.util.ThreadingUtils.*;

public class BouncrBackend implements AuthBackend<HttpRequest, Map<String, Object>> {
    private PrivateKey privateKey;

    @Inject
    private JsonWebToken jwt;

    @Override
    public Map<String, Object> parse(HttpRequest request) {
        return some(request.getHeaders().get("x-bouncr-credential"),
                cred -> jwt.unsign(cred, privateKey, new TypeReference<Map<String, Object>>() {}))
                .orElse(null);
    }

    @Override
    public Principal authenticate(HttpRequest request, Map<String, Object> authenticationData) {
        if (authenticationData == null) return null;

        String account = (String) authenticationData.remove("sub");
        List<String> permissions = (List<String>) Optional.ofNullable(authenticationData.remove("permissions"))
                .orElse(Collections.emptyList());

        return new UserPermissionPrincipal(account, authenticationData, new HashSet<>(permissions));
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}
