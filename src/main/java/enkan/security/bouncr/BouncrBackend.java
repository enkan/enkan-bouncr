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
 * <p>On successful verification by {@link #parse}, {@link #authenticate} returns a
 * {@link UserPermissionPrincipal} populated from the {@code uid}, {@code sub}, and
 * {@code permissions} claims.
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
                    JwtHeader header = JwtProcessor.decodeHeader(cred);
                    validateAlgFamilyOrThrow(header);
                    byte[] payload;
                    if (publicKey != null) {
                        payload = JwtProcessor.verify(cred, publicKey);
                    } else {
                        // Align the SecretKeySpec algorithm with the declared JWT alg so strict
                        // JCA providers that validate key.getAlgorithm() against the Mac algorithm
                        // accept the key for HS384/HS512 as well as HS256.
                        payload = JwtProcessor.verify(cred, new SecretKeySpec(key, hmacJcaName(header)));
                    }
                    if (payload == null) return null;
                    return objectMapper.readValue(payload, new TypeReference<Map<String, Object>>() {});
                })
                .orElse(null);
    }

    /**
     * Constructs a {@link UserPermissionPrincipal} from the parsed JWT claims.
     *
     * <p><b>Note:</b> This method removes the {@code uid}, {@code sub}, and {@code permissions}
     * keys from {@code authenticationData}. The remaining entries become the principal's
     * profile map. Callers must not reuse the map after this call.
     *
     * @param request            the incoming HTTP request (not used directly)
     * @param authenticationData the claims map returned by {@link #parse}; modified in place
     * @return a {@link UserPermissionPrincipal}, or {@code null} if {@code authenticationData} is null
     */
    @Override
    public Principal authenticate(HttpRequest request, Map<String, Object> authenticationData) {
        if (authenticationData == null) return null;

        // Intentionally destructive: remove known fields so the remaining entries
        // form the 'profiles' map passed to UserPermissionPrincipal.
        Long id = Long.valueOf(Objects.toString(authenticationData.remove("uid"), "0"));
        String account = (String) authenticationData.remove("sub");
        @SuppressWarnings("unchecked")
        List<Object> permissions = Optional.ofNullable(authenticationData.remove("permissions"))
                .filter(List.class::isInstance)
                .map(v -> (List<Object>) v)
                .orElse(Collections.emptyList());
        Set<String> permissionSet = permissions.stream()
                .filter(Objects::nonNull)
                .map(Objects::toString)
                .collect(Collectors.toSet());
        return new UserPermissionPrincipal(id, account, authenticationData, permissionSet);
    }

    /**
     * Resolves the JCA algorithm name for a {@link SecretKeySpec} from the JWT header alg.
     * Defaults to HmacSHA256 when the header is missing or the alg is not a recognised HS family.
     */
    private String hmacJcaName(JwtHeader header) {
        if (header == null || header.alg() == null) return "HmacSHA256";
        return switch (header.alg()) {
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };
    }

    /**
     * Validates that the JWT header's alg family matches the configured key type.
     * Asymmetric key (publicKey) requires RS/PS/ES algorithms; symmetric key requires HS algorithms.
     * Throws MisconfigurationException when they do not match.
     * Returns silently when the token is unparseable (let verify() handle it).
     */
    private void validateAlgFamilyOrThrow(JwtHeader header) {
        if (header == null || header.alg() == null) return;
        // Defence-in-depth: reject alg:none explicitly at this layer, independent of
        // any downstream library behaviour. Case-insensitive to block crafted variants.
        if ("none".equalsIgnoreCase(header.alg())) {
            throw new enkan.exception.MisconfigurationException("bouncr.ALG_NONE_NOT_ALLOWED");
        }
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
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }
}
