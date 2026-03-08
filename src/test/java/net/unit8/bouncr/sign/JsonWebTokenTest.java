package net.unit8.bouncr.sign;

import tools.jackson.core.type.TypeReference;
import enkan.exception.MisconfigurationException;
import enkan.system.EnkanSystem;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class JsonWebTokenTest {
    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private EnkanSystem system;
    private JsonWebToken jwt;

    @BeforeEach
    public void setupComponent() {
        system = EnkanSystem.of("jwt", new JsonWebToken());
        system.start();
        jwt = system.getComponent("jwt");
    }

    @AfterEach
    public void shutdownComponent() {
        system.stop();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private String sign(Map<String, Object> claims, String alg, byte[] key) {
        return jwt.sign(claims, new JwtHeader(alg, null), key);
    }

    private String sign(Map<String, Object> claims, String alg, PrivateKey key) {
        return jwt.sign(claims, new JwtHeader(alg, null), key);
    }

    // --- HMAC algorithms ---

    @ParameterizedTest
    @ValueSource(strings = {"HS256", "HS384", "HS512"})
    public void hmacRoundtrip(String alg) {
        byte[] key = "my-test-secret-key-for-hmac-tests".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> claims = Map.of("sub", "kawasima");

        String token = sign(claims, alg, key);
        Map<String, Object> result = jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    @Test
    public void hmacWrongKeyReturnsNull() {
        byte[] key = "correct-key".getBytes(StandardCharsets.UTF_8);
        byte[] wrongKey = "wrong-key-xx".getBytes(StandardCharsets.UTF_8);
        String token = sign(Map.of("sub", "user"), "HS256", key);
        assertThat(jwt.unsign(token, wrongKey, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    // --- RSA algorithms ---

    @ParameterizedTest
    @ValueSource(strings = {"RS256", "RS384", "RS512"})
    public void rsaRoundtrip(String alg) throws Exception {
        KeyPair keyPair = generateKeyPair();
        Map<String, Object> claims = Map.of("sub", "kawasima");

        String token = sign(claims, alg, keyPair.getPrivate());
        Map<String, Object> result = jwt.unsign(token, keyPair.getPublic(), new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    @Test
    public void rs256() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String message = sign(Map.of("sub", "kawasima"), "RS256", keyPair.getPrivate());
        Map<String, Object> claim = jwt.unsign(message, keyPair.getPublic(), new TypeReference<Map<String, Object>>() {});
        assertThat(claim).containsEntry("sub", "kawasima");
    }

    @Test
    public void badKey() throws Exception {
        KeyPair keyPair = generateKeyPair();
        KeyPair anotherKeyPair = generateKeyPair();
        String message = sign(Map.of("sub", "kawasima"), "RS256", keyPair.getPrivate());
        assertThat(jwt.unsign(message, anotherKeyPair.getPublic(), new TypeReference<Map<String, Object>>() {})).isNull();
    }

    // --- PSS algorithms ---

    @ParameterizedTest
    @ValueSource(strings = {"PS256", "PS384", "PS512"})
    public void pssRoundtrip(String alg) throws Exception {
        KeyPair keyPair = generateKeyPair();
        Map<String, Object> claims = Map.of("sub", "kawasima");

        String token = sign(claims, alg, keyPair.getPrivate());
        Map<String, Object> result = jwt.unsign(token, keyPair.getPublic(), new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    // --- HMAC with HS256 (backward compat test) ---

    @Test
    public void hs256() {
        byte[] sharedSecret = "my-test-secret-key-for-hmac".getBytes(StandardCharsets.UTF_8);
        String message = sign(Map.of("sub", "kawasima"), "HS256", sharedSecret);
        Map<String, Object> claim = jwt.unsign(message, sharedSecret, new TypeReference<Map<String, Object>>() {});
        assertThat(claim).containsEntry("sub", "kawasima");
    }

    // --- unsign with Class<T> overload ---
    @Test
    public void unsignWithClassOverload() throws Exception {
        KeyPair keyPair = generateKeyPair();
        String token = sign(Map.of("sub", "kawasima"), "RS256", keyPair.getPrivate());
        Map<String, Object> result = jwt.<Map<String, Object>>unsign(token, keyPair.getPublic(),
                new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    @Test
    public void unsignHmacWithClassOverload() {
        byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
        String token = sign(Map.of("sub", "kawasima"), "HS256", key);
        Map<String, Object> result = jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    // --- sign with JwtClaim ---

    @Test
    public void signWithJwtClaim() throws Exception {
        KeyPair keyPair = generateKeyPair();
        JwtClaim claim = new JwtClaim();
        claim.setSub("kawasima");
        claim.setIss("test-issuer");

        String token = jwt.sign(claim, new JwtHeader("RS256", null), keyPair.getPrivate());
        Map<String, Object> result = jwt.unsign(token, keyPair.getPublic(), new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
        assertThat(result).containsEntry("iss", "test-issuer");
    }

    @Test
    public void signJwtClaimWithHmac() {
        byte[] key = "hmac-secret-key".getBytes(StandardCharsets.UTF_8);
        JwtClaim claim = new JwtClaim();
        claim.setSub("kawasima");

        String token = jwt.sign(claim, new JwtHeader("HS256", null), key);
        Map<String, Object> result = jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima");
    }

    // --- security: alg:none rejection ---

    @Test
    public void algNoneIsRejected() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String fakeToken = enc.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8))
                + "." + enc.encodeToString("{\"sub\":\"attacker\"}".getBytes(StandardCharsets.UTF_8)) + ".";
        byte[] dummyKey = "any-key".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> jwt.unsign(fakeToken, dummyKey, new TypeReference<Map<String, Object>>() {}))
                .isInstanceOf(MisconfigurationException.class);
    }

    @Test
    public void unknownAlgorithmIsRejected() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String fakeToken = enc.encodeToString("{\"alg\":\"XY999\"}".getBytes(StandardCharsets.UTF_8))
                + "." + enc.encodeToString("{\"sub\":\"x\"}".getBytes(StandardCharsets.UTF_8)) + ".sig";
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> jwt.unsign(fakeToken, key, new TypeReference<Map<String, Object>>() {}))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- time claim validation (RFC 7519 §4.1.4, §4.1.5) ---

    @Test
    public void expiredTokenReturnsNull() {
        byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
        long pastEpoch = Instant.now().getEpochSecond() - 3600;
        Map<String, Object> claims = Map.of("sub", "user", "exp", pastEpoch);
        String token = sign(claims, "HS256", key);
        assertThat(jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    @Test
    public void notYetValidTokenReturnsNull() {
        byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
        long futureEpoch = Instant.now().getEpochSecond() + 3600;
        Map<String, Object> claims = Map.of("sub", "user", "nbf", futureEpoch);
        String token = sign(claims, "HS256", key);
        assertThat(jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    @Test
    public void validExpTokenIsAccepted() {
        byte[] key = "secret".getBytes(StandardCharsets.UTF_8);
        long futureEpoch = Instant.now().getEpochSecond() + 3600;
        Map<String, Object> claims = Map.of("sub", "user", "exp", futureEpoch);
        String token = sign(claims, "HS256", key);
        assertThat(jwt.unsign(token, key, new TypeReference<Map<String, Object>>() {}))
                .containsEntry("sub", "user");
    }

    // --- malformed token edge cases ---

    @Test
    public void twoSegmentTokenReturnsNull() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThat(jwt.unsign("header.payload", key, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    @Test
    public void singleSegmentTokenReturnsNull() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThat(jwt.unsign("onlyone", key, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    @Test
    public void emptyTokenReturnsNull() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThat(jwt.unsign("", key, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    // --- decodePayload ---

    @Test
    public void decodePayloadDirectly() {
        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        String encoded = enc.encodeToString("{\"sub\":\"kawasima\",\"iss\":\"test\"}".getBytes(StandardCharsets.UTF_8));
        Map<String, Object> result = jwt.decodePayload(encoded, new TypeReference<Map<String, Object>>() {});
        assertThat(result).containsEntry("sub", "kawasima").containsEntry("iss", "test");
    }

    @Test
    public void decodePayloadReturnsNullForNull() {
        assertThat(jwt.decodePayload(null, new TypeReference<Map<String, Object>>() {})).isNull();
    }

    // --- guard: component not started ---

    @Test
    public void decodePayloadThrowsWhenNotStarted() {
        JsonWebToken unstartedJwt = new JsonWebToken();
        assertThatThrownBy(() -> unstartedJwt.decodePayload("eyJ0ZXN0IjoxfQ", new TypeReference<Map<String, Object>>() {}))
                .isInstanceOf(MisconfigurationException.class);
    }

    @Test
    public void unsignThrowsWhenNotStarted() {
        JsonWebToken unstartedJwt = new JsonWebToken();
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> unstartedJwt.unsign("a.b.c", key, new TypeReference<Map<String, Object>>() {}))
                .isInstanceOf(MisconfigurationException.class);
    }

    @Test
    public void signThrowsWhenNotStarted() {
        JsonWebToken unstartedJwt = new JsonWebToken();
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> unstartedJwt.sign(Map.of("sub", "x"), new JwtHeader("HS256", null), key))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- guard: null signing key ---

    @Test
    public void signThrowsWhenKeyIsNull() {
        assertThatThrownBy(() -> jwt.sign("payload", new JwtHeader("HS256", null), (byte[]) null))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- guard: alg:none in sign() ---

    @Test
    public void signThrowsWhenAlgIsNone() {
        byte[] key = "key".getBytes(StandardCharsets.UTF_8);
        assertThatThrownBy(() -> jwt.sign(Map.of("sub", "x"), new JwtHeader("none", null), key))
                .isInstanceOf(MisconfigurationException.class);
    }
}
