package net.unit8.bouncr.sign;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import enkan.collection.OptionMap;
import enkan.component.ComponentLifecycle;
import enkan.component.SystemComponent;
import enkan.exception.MisconfigurationException;
import enkan.exception.UnreachableException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import static enkan.util.ThreadingUtils.some;

public class JsonWebToken extends SystemComponent {
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
            "none",  "none"
            );

    private String encodeHeader(JwtHeader header) {
        return some(header,
                h -> mapper.writeValueAsBytes(h),
                json -> base64Encoder.encodeToString(json))
                .orElse(null);
    }

    @SuppressWarnings("unchecked")
    public <T> T decodePayload(String encoded, TypeReference<T> payloadType) {
        return some(encoded,
                enc -> new String(base64Decoder.decode(enc)),
                plain -> (T) mapper.readValue(plain, payloadType))
                .orElse(null);
    }

    private boolean verifySignature(String alg, String signature, byte[] key, String header, String payload) {
        String signAlgorithm = ALGORITHMS.getString(alg);
        if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", alg);
        if (signAlgorithm.equals("none")) {
            return true;
        }

        try {
            if (signAlgorithm.startsWith("Hmac")) {
                SecretKeySpec keySpec = new SecretKeySpec(key, signAlgorithm);
                Mac mac = Mac.getInstance(signAlgorithm, "BC");
                mac.init(keySpec);
                mac.update(String.join(".", header, payload).getBytes());
                return Objects.equals(signature, base64Encoder.encodeToString(mac.doFinal()));
            } else {
                Signature signer = Signature.getInstance(signAlgorithm, "BC");
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
                signer.initSign(privateKey, prng);
                signer.update(String.join(".", header, payload).getBytes());
                return Objects.equals(signature, base64Encoder.encodeToString(signer.sign()));
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UnreachableException(e);
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            return false;
        }

    }

    public <T> T unsign(String message, byte[] key, TypeReference<T> typeReference) {
        String[] tokens = message.split("\\.", 3);
        if (tokens.length != 3) return null;
        try {
            JwtHeader header = mapper.readValue(base64Decoder.decode(tokens[0]), JwtHeader.class);
            if (verifySignature(header.getAlg(), tokens[2], key, tokens[0], tokens[1])) {
                return decodePayload(/*Payload*/tokens[1], typeReference);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T unsign(String message, byte[] key, Class<T> claimClass) {
        return unsign(message, key, new TypeReference<T>() {
            @Override
            public Type getType() { return claimClass; }
        });
    }

    public <T> T unsign(String message, PrivateKey pkey, TypeReference<T> typeReference) {
        return unsign(message, pkey.getEncoded(), typeReference);
    }

    public <T> T unsign(String message, PrivateKey pkey, Class<T> claimClass) {
        return unsign(message, pkey, new TypeReference<T>() {
            @Override
            public Type getType() { return claimClass; }
        });
    }

    public String sign(String payload, JwtHeader header, byte[] key) {
        String encodedHeader = encodeHeader(header);
        try {
            String signAlgorithm = ALGORITHMS.getString(header.getAlg());
            if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", header.getAlg());
            String encodedSignature = "";
            if (!signAlgorithm.equals("none")) {
                if (signAlgorithm.startsWith("Hmac")) {
                    SecretKeySpec keySpec = new SecretKeySpec(key, signAlgorithm);
                    Mac mac = Mac.getInstance(signAlgorithm);
                    mac.init(keySpec);
                    mac.update(String.join(".", encodedHeader, payload).getBytes());
                    encodedSignature = base64Encoder.encodeToString(mac.doFinal());
                } else {
                    Signature signature = Signature.getInstance(signAlgorithm, "BC");
                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
                    signature.initSign(privateKey, prng);
                    signature.update(String.join(".", encodedHeader, payload).getBytes());
                    encodedSignature = base64Encoder.encodeToString(signature.sign());
                }
            }
            return String.join(".", encodedHeader, payload, encodedSignature);
        } catch (NoSuchAlgorithmException e) {
            throw new UnreachableException(e);
        } catch (NoSuchProviderException e) {
            throw new MisconfigurationException(""); //TODO
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            throw new MisconfigurationException(""); //TODO
        }
    }

    public String sign(Map<String, Object> claims, JwtHeader header, byte[] key) {
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);

    }

    public String sign(Map<String, Object> claims, JwtHeader header, PrivateKey key) {
        return sign(claims, header, key.getEncoded());
    }

    public String sign(JwtClaim claims, JwtHeader header, byte[] key) {
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);

    }

    public String sign(JwtClaim claims, JwtHeader header, PrivateKey key) {
        return sign(claims, header, key.getEncoded());
    }

    @Override
    protected ComponentLifecycle lifecycle() {
        return new ComponentLifecycle<JsonWebToken>() {
            @Override
            public void start(JsonWebToken component) {
                component.mapper = new ObjectMapper();
                component.mapper.registerModule(new JavaTimeModule());
                component.mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
                component.mapper.configure(DeserializationFeature.UNWRAP_SINGLE_VALUE_ARRAYS, true);
                component.mapper.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false);
                component.mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

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
