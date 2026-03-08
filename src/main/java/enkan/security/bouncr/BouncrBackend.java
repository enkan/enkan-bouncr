package enkan.security.bouncr;

import tools.jackson.core.type.TypeReference;
import enkan.data.HttpRequest;
import enkan.security.AuthBackend;
import net.unit8.bouncr.sign.JsonWebToken;

import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PublicKey;
import java.util.*;
import java.util.Base64;
import java.util.stream.Collectors;

import static enkan.util.ThreadingUtils.some;

public class BouncrBackend implements AuthBackend<HttpRequest, Map<String, Object>> {
    private PublicKey publicKey;
    private byte[] key;

    @Inject
    private JsonWebToken jwt;

    @Override
    public Map<String, Object> parse(HttpRequest request) {
        if (jwt == null) {
            throw new enkan.exception.MisconfigurationException("bouncr.JWT_COMPONENT_NOT_INJECTED");
        }
        if (publicKey != null && key != null) {
            throw new enkan.exception.MisconfigurationException("bouncr.AMBIGUOUS_KEY_CONFIG");
        }
        if (publicKey == null && key == null) {
            throw new enkan.exception.MisconfigurationException("bouncr.NO_KEY_CONFIGURED");
        }
        return some(request.getHeaders().get("x-bouncr-credential"),
                cred -> {
                    validateAlgFamilyOrThrow(cred);
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
        List<String> permissions = Optional.ofNullable(authenticationData.remove("permissions"))
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

    /**
     * Validates that the JWT header's alg family matches the configured key type.
     * Asymmetric key (publicKey) requires RS/PS/ES algorithms; symmetric key requires HS algorithms.
     * Throws MisconfigurationException when they do not match.
     * Returns silently when the token is unparseable (let unsign() handle it).
     */
    private void validateAlgFamilyOrThrow(String token) {
        try {
            String[] parts = token.split("\\.", 3);
            if (parts.length < 2) return;
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]),
                    java.nio.charset.StandardCharsets.UTF_8);
            // Extract "alg" value with a simple string search to avoid a Jackson dependency here
            int algIdx = headerJson.indexOf("\"alg\"");
            if (algIdx < 0) return;
            int colon = headerJson.indexOf(':', algIdx);
            if (colon < 0) return;
            int start = headerJson.indexOf('"', colon) + 1;
            int end   = headerJson.indexOf('"', start);
            if (start <= 0 || end <= start) return;
            String alg = headerJson.substring(start, end);
            boolean isHmac = alg.startsWith("HS");
            if (publicKey != null && isHmac) {
                throw new enkan.exception.MisconfigurationException("bouncr.ALG_KEY_FAMILY_MISMATCH",
                        "Token uses HMAC algorithm '" + alg + "' but an asymmetric publicKey is configured.");
            }
            if (key != null && !isHmac) {
                throw new enkan.exception.MisconfigurationException("bouncr.ALG_KEY_FAMILY_MISMATCH",
                        "Token uses asymmetric algorithm '" + alg + "' but a symmetric key is configured.");
            }
        } catch (IllegalArgumentException e) {
            // Malformed Base64 — let unsign() return null naturally
        }
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
