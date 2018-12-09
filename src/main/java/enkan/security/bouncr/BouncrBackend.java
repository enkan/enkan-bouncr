package enkan.security.bouncr;

import com.fasterxml.jackson.core.type.TypeReference;
import enkan.data.HttpRequest;
import enkan.security.AuthBackend;
import net.unit8.bouncr.sign.JsonWebToken;

import javax.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PrivateKey;
import java.util.*;
import java.util.stream.Collectors;

import static enkan.util.ThreadingUtils.some;

public class BouncrBackend implements AuthBackend<HttpRequest, Map<String, Object>> {
    private PrivateKey privateKey;
    private byte[] key;

    @Inject
    private JsonWebToken jwt;

    @Override
    public Map<String, Object> parse(HttpRequest request) {
        return some(request.getHeaders().get("x-bouncr-credential"),
                cred -> {
                    if (privateKey != null) {
                        return jwt.unsign(cred, privateKey, new TypeReference<Map<String, Object>>() {});
                    } else {
                        return jwt.unsign(cred, key, new TypeReference<Map<String, Object>>() {});
                    }
                })
                .orElse(null);
    }

    @SuppressWarnings("unchecked")
    @Override
    public Principal authenticate(HttpRequest request, Map<String, Object> authenticationData) {
        if (authenticationData == null) return null;

        String account = (String) authenticationData.remove("sub");
        List permissions = Optional.ofNullable(authenticationData.remove("permissions"))
                .filter(List.class::isInstance)
                .map(List.class::cast)
                .orElse(Collections.EMPTY_LIST);
        return new UserPermissionPrincipal(account, authenticationData,
                (Set<String>) permissions.stream()
                        .filter(Objects::nonNull)
                        .map(Objects::toString)
                        .collect(Collectors.toSet())
        );
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public void setKey(String key) {
        this.key = key.getBytes(StandardCharsets.ISO_8859_1);
    }

    public void setKey(byte[] key) {
        this.key = key;
    }
}
