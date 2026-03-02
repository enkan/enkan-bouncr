package enkan.security.bouncr;

import com.fasterxml.jackson.core.type.TypeReference;
import enkan.data.HttpRequest;
import enkan.security.AuthBackend;
import net.unit8.bouncr.sign.JsonWebToken;

import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;

import static enkan.util.ThreadingUtils.some;

public class BouncrBackend implements AuthBackend<HttpRequest, Map<String, Object>> {
    private PublicKey publicKey;
    private byte[] key;

    @Inject
    private JsonWebToken jwt;

    @Override
    public Map<String, Object> parse(HttpRequest request) {
        if (publicKey != null && key != null) {
            throw new enkan.exception.MisconfigurationException("bouncr.AMBIGUOUS_KEY_CONFIG",
                    "Configure either publicKey (RSA) or key (HMAC), not both.");
        }
        return some(request.getHeaders().get("x-bouncr-credential"),
                cred -> {
                    if (publicKey != null) {
                        return jwt.unsign(cred, publicKey, new TypeReference<Map<String, Object>>() {});
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

        // Intentionally destructive: remove known fields so the remaining entries
        // form the 'profiles' map passed to UserPermissionPrincipal.
        Long id = Long.valueOf(Objects.toString(authenticationData.remove("uid"), "0"));
        String account = (String) authenticationData.remove("sub");
        List permissions = Optional.ofNullable(authenticationData.remove("permissions"))
                .filter(List.class::isInstance)
                .map(List.class::cast)
                .orElse(Collections.emptyList());
        return new UserPermissionPrincipal(id, account, authenticationData,
                (Set<String>) permissions.stream()
                        .filter(Objects::nonNull)
                        .map(Objects::toString)
                        .collect(Collectors.toSet())
        );
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void setKey(String key) {
        this.key = key.getBytes(StandardCharsets.UTF_8);
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

    public void setJwt(JsonWebToken jwt) {
        this.jwt = jwt;
    }
}
