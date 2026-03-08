package net.unit8.bouncr.sign;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * JWT JOSE Header per RFC 7519 §5 / RFC 7515 §4.
 *
 * <p>{@code typ} is typically {@code "JWT"}. {@code alg} identifies the signing algorithm
 * (e.g. {@code "HS256"}, {@code "RS256"}, {@code "ES256"}). {@code kid} is an optional
 * key identifier. Fields with {@code null} values are excluded from serialization.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JwtHeader(String typ, String alg, String kid) {
}
