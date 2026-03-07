package enkan.security.bouncr;

import enkan.collection.Headers;
import enkan.data.DefaultHttpRequest;
import enkan.data.HttpRequest;
import enkan.exception.MisconfigurationException;
import enkan.system.EnkanSystem;
import net.unit8.bouncr.sign.JsonWebToken;
import net.unit8.bouncr.sign.JwtHeader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class BouncrBackendTest {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private EnkanSystem system;
    private JsonWebToken jwt;

    @BeforeEach
    public void setup() {
        system = EnkanSystem.of("jwt", new JsonWebToken());
        system.start();
        jwt = system.getComponent("jwt");
    }

    @AfterEach
    public void teardown() {
        system.stop();
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private HttpRequest requestWithCredential(String credential) {
        DefaultHttpRequest req = new DefaultHttpRequest();
        req.setHeaders(Headers.of("x-bouncr-credential", credential));
        return req;
    }

    private HttpRequest requestWithoutCredential() {
        DefaultHttpRequest req = new DefaultHttpRequest();
        req.setHeaders(Headers.empty());
        return req;
    }

    private String signHmac(Map<String, Object> claims, byte[] key) {
        JwtHeader header = new JwtHeader();
        header.setAlg("HS256");
        return jwt.sign(claims, header, key);
    }

    private String signRsa(Map<String, Object> claims, PrivateKey key) {
        JwtHeader header = new JwtHeader();
        header.setAlg("RS256");
        return jwt.sign(claims, header, key);
    }

    // --- parse() ---

    private BouncrBackend backendWithKey(byte[] key) {
        BouncrBackend backend = new BouncrBackend();
        backend.setJwt(jwt);
        backend.setKey(key);
        return backend;
    }

    private BouncrBackend backendWithPublicKey(java.security.PublicKey publicKey) {
        BouncrBackend backend = new BouncrBackend();
        backend.setJwt(jwt);
        backend.setPublicKey(publicKey);
        return backend;
    }

    @Test
    public void parseReturnsNullWhenNoCredentialHeader() {
        BouncrBackend backend = backendWithKey("secret".getBytes(StandardCharsets.UTF_8));
        assertThat(backend.parse(requestWithoutCredential())).isNull();
    }

    @Test
    public void parseHmacToken() {
        byte[] key = "my-hmac-secret".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "kawasima");
        claims.put("uid", 7);
        String token = signHmac(claims, key);

        BouncrBackend backend = backendWithKey(key);
        Map<String, Object> result = backend.parse(requestWithCredential(token));
        assertThat(result).containsEntry("sub", "kawasima");
    }

    @Test
    public void parseRsaToken() throws Exception {
        KeyPair keyPair = generateKeyPair();
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "kawasima");
        claims.put("uid", 7);
        String token = signRsa(claims, keyPair.getPrivate());

        BouncrBackend backend = backendWithPublicKey(keyPair.getPublic());
        Map<String, Object> result = backend.parse(requestWithCredential(token));
        assertThat(result).containsEntry("sub", "kawasima");
    }

    @Test
    public void parseReturnsNullForWrongSignature() {
        byte[] key = "correct-key".getBytes(StandardCharsets.UTF_8);
        byte[] wrongKey = "wrong-key-xx".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "kawasima");
        String token = signHmac(claims, key);

        BouncrBackend backend = backendWithKey(wrongKey);
        assertThat(backend.parse(requestWithCredential(token))).isNull();
    }

    @Test
    public void parseThrowsWhenBothKeysConfigured() throws Exception {
        KeyPair keyPair = generateKeyPair();
        BouncrBackend backend = new BouncrBackend();
        backend.setJwt(jwt);
        backend.setPublicKey(keyPair.getPublic());
        backend.setKey("secret".getBytes(StandardCharsets.UTF_8));

        assertThatThrownBy(() -> backend.parse(requestWithoutCredential()))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- guard: no key configured ---

    @Test
    public void parseThrowsWhenNoKeyConfigured() {
        BouncrBackend backend = new BouncrBackend();
        backend.setJwt(jwt);
        assertThatThrownBy(() -> backend.parse(requestWithoutCredential()))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- guard: jwt not injected ---

    @Test
    public void parseThrowsWhenJwtNotInjected() {
        BouncrBackend backend = new BouncrBackend();
        backend.setKey("secret".getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> backend.parse(requestWithoutCredential()))
                .isInstanceOf(MisconfigurationException.class);
    }

    // --- authenticate() ---

    @Test
    public void authenticateReturnsNullForNullData() {
        BouncrBackend backend = new BouncrBackend();
        assertThat(backend.authenticate(requestWithoutCredential(), null)).isNull();
    }

    @Test
    public void authenticateBuildsCorrectPrincipal() {
        BouncrBackend backend = new BouncrBackend();
        Map<String, Object> data = new HashMap<>();
        data.put("uid", "42");
        data.put("sub", "kawasima");
        data.put("permissions", List.of("read", "write"));
        data.put("email", "test@example.com");

        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithoutCredential(), data);

        assertThat(principal.getId()).isEqualTo(42L);
        assertThat(principal.getName()).isEqualTo("kawasima");
        assertThat(principal.hasPermission("read")).isTrue();
        assertThat(principal.hasPermission("write")).isTrue();
        assertThat(principal.hasPermission("delete")).isFalse();
        // email remains in profiles after uid/sub/permissions are removed
        assertThat(principal.getProfiles()).containsEntry("email", "test@example.com");
    }

    @Test
    public void authenticateDefaultsUidToZeroWhenMissing() {
        BouncrBackend backend = new BouncrBackend();
        Map<String, Object> data = new HashMap<>();
        data.put("sub", "kawasima");
        data.put("permissions", List.of());

        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithoutCredential(), data);
        assertThat(principal.getId()).isEqualTo(0L);
    }

    @Test
    public void authenticateHandlesMissingPermissions() {
        BouncrBackend backend = new BouncrBackend();
        Map<String, Object> data = new HashMap<>();
        data.put("uid", "1");
        data.put("sub", "kawasima");

        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithoutCredential(), data);
        assertThat(principal.getPermissions()).isEmpty();
    }

    @Test
    public void authenticateFiltersNullPermissions() {
        BouncrBackend backend = new BouncrBackend();
        Map<String, Object> data = new HashMap<>();
        data.put("uid", "1");
        data.put("sub", "kawasima");
        data.put("permissions", new java.util.ArrayList<>(java.util.Arrays.asList("read", null, "write")));

        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithoutCredential(), data);
        assertThat(principal.getPermissions()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    public void authenticateRemainingFieldsBecomesProfiles() {
        BouncrBackend backend = new BouncrBackend();
        Map<String, Object> data = new HashMap<>();
        data.put("uid", "1");
        data.put("sub", "kawasima");
        data.put("permissions", List.of());
        data.put("locale", "ja");
        data.put("email", "k@example.com");

        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithoutCredential(), data);
        assertThat(principal.getProfiles()).containsKeys("locale", "email");
        assertThat(principal.getProfiles()).doesNotContainKeys("uid", "sub", "permissions");
    }

    // --- full flow ---

    @Test
    public void fullHmacFlow() {
        byte[] key = "integration-test-key".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> claims = new HashMap<>();
        claims.put("uid", 99);
        claims.put("sub", "testuser");
        claims.put("permissions", List.of("admin"));
        String token = signHmac(claims, key);

        BouncrBackend backend = backendWithKey(key);

        Map<String, Object> parsed = backend.parse(requestWithCredential(token));
        UserPermissionPrincipal principal = (UserPermissionPrincipal) backend.authenticate(requestWithCredential(token), parsed);

        assertThat(principal.getName()).isEqualTo("testuser");
        assertThat(principal.hasPermission("admin")).isTrue();
    }
}
