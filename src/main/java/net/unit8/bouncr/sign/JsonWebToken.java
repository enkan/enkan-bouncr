package net.unit8.bouncr.sign;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import enkan.collection.OptionMap;
import enkan.component.ComponentLifecycle;
import enkan.component.SystemComponent;
import enkan.exception.MisconfigurationException;
import enkan.exception.UnreachableException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import static enkan.util.ThreadingUtils.some;

public class JsonWebToken extends SystemComponent<JsonWebToken> {
    private ObjectMapper mapper;
    private Base64.Decoder base64Decoder;
    private Base64.Encoder base64Encoder;
    private SecureRandom prng;

    private static final OptionMap ALGORITHMS = OptionMap.of(
            "HS256", "HmacSHA256",
            "HS384", "HmacSHA384",
            "HS512", "HmacSHA512",
            "RS256", "SHA256withRSA",
            "RS384", "SHA384withRSA",
            "RS512", "SHA512withRSA",
            "PS256", "SHA256withRSAandMGF1",
            "PS384", "SHA384withRSAandMGF1",
            "PS512", "SHA512withRSAandMGF1",
            "ES256", "SHA256withECDSA",
            "ES384", "SHA384withECDSA",
            "ES512", "SHA512withECDSA",
            "none",  "none"
            );

    private void requireStarted() {
        if (mapper == null) {
            throw new MisconfigurationException("bouncr.JWT_NOT_STARTED");
        }
    }

    private String encodeHeader(JwtHeader header) {
        return some(header,
                h -> mapper.writeValueAsBytes(h),
                json -> base64Encoder.encodeToString(json))
                .orElse(null);
    }

    public <T> T decodePayload(String encoded, TypeReference<T> payloadType) {
        requireStarted();
        return some(encoded,
                enc -> new String(base64Decoder.decode(enc)),
                plain -> (T) mapper.readValue(plain, payloadType))
                .orElse(null);
    }

    /**
     * Validates exp and nbf claims per RFC 7519 §4.1.4 and §4.1.5.
     * Returns false if the token is expired, not yet valid, or has malformed time claims.
     */
    private boolean validateTimeClaims(Map<String, Object> claims) {
        long now = Instant.now().getEpochSecond();
        Object exp = claims.get("exp");
        if (exp != null) {
            try {
                if (toLong(exp) <= now) return false;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        Object nbf = claims.get("nbf");
        if (nbf != null) {
            try {
                if (toLong(nbf) > now) return false;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        return true;
    }

    private long toLong(Object value) {
        try {
            java.math.BigDecimal bd = new java.math.BigDecimal(value.toString())
                    .stripTrailingZeros();
            return bd.longValueExact();
        } catch (NumberFormatException | ArithmeticException e) {
            throw new IllegalArgumentException("Non-numeric or non-integer time claim: " + value, e);
        }
    }

    private boolean verifySignature(String alg, String signature, byte[] key, String header, String payload) {
        String signAlgorithm = ALGORITHMS.getString(alg);
        if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", alg);
        if (signAlgorithm.equals("none")) {
            throw new MisconfigurationException("bouncr.ALG_NONE_NOT_ALLOWED");
        }

        try {
            if (signAlgorithm.startsWith("Hmac")) {
                SecretKeySpec keySpec = new SecretKeySpec(key, signAlgorithm);
                Mac mac = Mac.getInstance(signAlgorithm, "BC");
                mac.init(keySpec);
                mac.update(String.join(".", header, payload).getBytes(StandardCharsets.US_ASCII));
                return Objects.equals(signature, base64Encoder.encodeToString(mac.doFinal()));
            } else {
                Signature verifier = Signature.getInstance(signAlgorithm, "BC");
                String keyAlg = signAlgorithm.contains("ECDSA") ? "EC" : "RSA";
                KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
                PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
                verifier.initVerify(publicKey);
                verifier.update(String.join(".", header, payload).getBytes(StandardCharsets.US_ASCII));
                return verifier.verify(base64Decoder.decode(signature));
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UnreachableException(e);
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            return false;
        }

    }

    public <T> T unsign(String message, byte[] key, TypeReference<T> typeReference) {
        requireStarted();
        String[] tokens = message.split("\\.", 3);
        if (tokens.length != 3) return null;
        JwtHeader header = mapper.readValue(base64Decoder.decode(tokens[0]), JwtHeader.class);
        if (!verifySignature(header.alg(), tokens[2], key, tokens[0], tokens[1])) {
            return null;
        }
        String payloadJson = new String(base64Decoder.decode(tokens[1]), StandardCharsets.UTF_8);
        Object payload = mapper.readValue(payloadJson, Object.class);
        if (payload instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> claims = (Map<String, Object>) payload;
            if (!validateTimeClaims(claims)) {
                return null;
            }
        }
        return mapper.convertValue(payload, typeReference);
    }

    public <T> T unsign(String message, byte[] key, Class<T> claimClass) {
        return unsign(message, key, new TypeReference<T>() {
            @Override
            public Type getType() { return claimClass; }
        });
    }

    public <T> T unsign(String message, PublicKey pkey, TypeReference<T> typeReference) {
        return unsign(message, pkey.getEncoded(), typeReference);
    }

    public <T> T unsign(String message, PublicKey pkey, Class<T> claimClass) {
        return unsign(message, pkey, new TypeReference<T>() {
            @Override
            public Type getType() { return claimClass; }
        });
    }

    public String sign(String payload, JwtHeader header, byte[] key) {
        requireStarted();
        if (key == null) {
            throw new MisconfigurationException("bouncr.SIGNING_KEY_IS_NULL");
        }
        String encodedHeader = encodeHeader(header);
        try {
            String signAlgorithm = ALGORITHMS.getString(header.alg());
            if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", header.alg());
            if (signAlgorithm.equals("none")) {
                throw new MisconfigurationException("bouncr.ALG_NONE_NOT_ALLOWED");
            }
            String encodedSignature;
            if (signAlgorithm.startsWith("Hmac")) {
                SecretKeySpec keySpec = new SecretKeySpec(key, signAlgorithm);
                Mac mac = Mac.getInstance(signAlgorithm);
                mac.init(keySpec);
                mac.update(String.join(".", encodedHeader, payload).getBytes(StandardCharsets.US_ASCII));
                encodedSignature = base64Encoder.encodeToString(mac.doFinal());
            } else {
                Signature signature = Signature.getInstance(signAlgorithm, "BC");
                String keyAlg = signAlgorithm.contains("ECDSA") ? "EC" : "RSA";
                KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
                signature.initSign(privateKey, prng);
                signature.update(String.join(".", encodedHeader, payload).getBytes(StandardCharsets.US_ASCII));
                encodedSignature = base64Encoder.encodeToString(signature.sign());
            }
            return String.join(".", encodedHeader, payload, encodedSignature);
        } catch (NoSuchAlgorithmException e) {
            throw new UnreachableException(e);
        } catch (NoSuchProviderException e) {
            throw new MisconfigurationException("bouncr.NO_SUCH_CRYPTO_PROVIDER",
                    "BouncyCastle provider is not registered. Add Security.addProvider(new BouncyCastleProvider()).");
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            throw new MisconfigurationException("bouncr.INVALID_SIGNING_KEY",
                    "The private key is invalid or incompatible with the signing algorithm.");
        }
    }

    public String sign(Map<String, Object> claims, JwtHeader header, byte[] key) {
        requireStarted();
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);
    }

    public String sign(Map<String, Object> claims, JwtHeader header, PrivateKey key) {
        if (key == null) {
            throw new MisconfigurationException("bouncr.SIGNING_KEY_IS_NULL");
        }
        return sign(claims, header, key.getEncoded());
    }

    public String sign(JwtClaim claims, JwtHeader header, byte[] key) {
        requireStarted();
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);
    }

    public String sign(JwtClaim claims, JwtHeader header, PrivateKey key) {
        if (key == null) {
            throw new MisconfigurationException("bouncr.SIGNING_KEY_IS_NULL");
        }
        return sign(claims, header, key.getEncoded());
    }

    @Override
    protected ComponentLifecycle<JsonWebToken> lifecycle() {
        return new ComponentLifecycle<JsonWebToken>() {
            @Override
            public void start(JsonWebToken component) {
                component.mapper = JsonMapper.builder()
                        .enable(DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS)
                        .enable(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
                        .disable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES)
                        .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                        .build();

                component.base64Decoder = Base64.getUrlDecoder();
                component.base64Encoder = Base64.getUrlEncoder().withoutPadding();
                if (component.prng == null) {
                    component.prng = new SecureRandom();
                }
            }

            @Override
            public void stop(JsonWebToken component) {
                component.mapper = null;
            }
        };
    }

    public void setPrng(SecureRandom prng) {
        this.prng = prng;
    }
}
