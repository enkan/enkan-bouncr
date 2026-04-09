package enkan.security.bouncr;

import enkan.web.data.HttpRequest;
import enkan.security.AuthBackend;
import enkan.web.jwt.JwtHeader;
import enkan.web.jwt.JwtProcessor;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;

import static enkan.util.ThreadingUtils.some;

/**
 * Enkan {@link AuthBackend} that authenticates requests by verifying a JWT carried in the
 * {@code x-bouncr-credential} HTTP header.
 *
 * <p>Configure exactly one of:
 * <ul>
 *   <li>{@link #setKey(String)} / {@link #setKey(byte[])} — HMAC shared secret (HS256/HS384/HS512)</li>
 *   <li>{@link #setPublicKey(PublicKey)} — RSA or EC public key (RS/PS/ES family algorithms)</li>
 * </ul>
 *
 * <p>On successful verification, {@link #authenticate} returns a {@link UserPermissionPrincipal}
 * populated from the {@code uid}, {@code sub}, and {@code permissions} claims.
 */
public class BouncrBackend implements AuthBackend<HttpRequest, Map<String, Object>> {
    private PublicKey publicKey;
    private byte[] key;
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Map<String, Object> parse(HttpRequest request) {
        if (publicKey != null && key != null) {
            throw new enkan.exception.MisconfigurationException("bouncr.AMBIGUOUS_KEY_CONFIG");
        }
        if (publicKey == null && key == null) {
            throw new enkan.exception.MisconfigurationException("bouncr.NO_KEY_CONFIGURED");
        }
        return some(request.getHeaders().get("x-bouncr-credential"),
                cred -> {
                    validateAlgFamilyOrThrow(cred);
                    byte[] payload;
                    if (publicKey != null) {
                        payload = JwtProcessor.verify(cred, publicKey);
                    } else {
                        // SecretKeySpec algorithm name is for documentation only; JcaVerifier
                        // determines the actual MAC algorithm from the JWT header alg field.
                        payload = JwtProcessor.verify(cred, new SecretKeySpec(key, "HmacSHA256"));
                    }
                    if (payload == null) return null;
                    return objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {});
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
     * Returns silently when the token is unparseable (let verify() handle it).
     */
    private void validateAlgFamilyOrThrow(String token) {
        JwtHeader header = JwtProcessor.decodeHeader(token);
        if (header == null || header.alg() == null) return;
        boolean isHmac = header.alg().startsWith("HS");
        if (publicKey != null && isHmac) {
            throw new enkan.exception.MisconfigurationException("bouncr.ALG_KEY_FAMILY_MISMATCH");
        }
        if (key != null && !isHmac) {
            throw new enkan.exception.MisconfigurationException("bouncr.ALG_KEY_FAMILY_MISMATCH");
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

    /**
     * Overrides the default {@link ObjectMapper} used to deserialize JWT payload bytes.
     * Useful when a pre-configured shared mapper (e.g. with custom deserializers) is required.
     */
    public void setObjectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }
}
