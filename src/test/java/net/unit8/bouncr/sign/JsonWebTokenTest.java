package net.unit8.bouncr.sign;

import com.fasterxml.jackson.core.type.TypeReference;
import enkan.system.EnkanSystem;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.*;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

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

    private PrivateKey generatePrivateKey() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        return pair.getPrivate();
    }

    private String createMessageRS256(PrivateKey pkey) {
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("sub", "kawasima");

        JwtHeader header = new JwtHeader();
        header.setAlg("RS256");

        return jwt.sign(claim, header, pkey);
    }

    private String createMessageHS256(PrivateKey pkey) {
        HashMap<String, Object> claim = new HashMap<>();
        claim.put("sub", "kawasima");

        JwtHeader header = new JwtHeader();
        header.setAlg("HS256");

        return jwt.sign(claim, header, pkey);
    }

    @Test
    public void rs256() throws Exception {
        PrivateKey pkey = generatePrivateKey();

        String message = createMessageRS256(pkey);
        Map<String,Object> claim = jwt.unsign(message, pkey, new TypeReference<Map<String, Object>>() {});
        assertThat(claim).containsEntry("sub", "kawasima");
    }

    @Test
    public void hs256() throws Exception {
        PrivateKey pkey = generatePrivateKey();

        String message = createMessageHS256(pkey);
        Map<String,Object> claim = jwt.unsign(message, pkey, new TypeReference<Map<String, Object>>() {});
        assertThat(claim).containsEntry("sub", "kawasima");
    }

    @Test
    public void badKey() throws Exception {
        PrivateKey pkey = generatePrivateKey();
        PrivateKey anotherKey = generatePrivateKey();

        String message = createMessageRS256(pkey);
        Map<String,Object> claim = jwt.unsign(message, anotherKey, new TypeReference<Map<String, Object>>() {});
        assertThat(claim).isNull();
    }
}
