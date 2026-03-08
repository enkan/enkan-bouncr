package net.unit8.bouncr.sign;

/** JWT JOSE Header per RFC 7519 §5 / RFC 7515 §4. */
public record JwtHeader(String typ, String alg, String kid) {
}
