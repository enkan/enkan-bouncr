package net.unit8.bouncr.sign;

import com.fasterxml.jackson.annotation.JsonInclude;

/** JWT JOSE Header per RFC 7519 §5 / RFC 7515 §4. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record JwtHeader(String typ, String alg, String kid) {
}
