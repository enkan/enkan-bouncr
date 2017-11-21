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

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Type;
import java.security.*;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import static enkan.util.ThreadingUtils.*;

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

    public <T> T decodePayload(String encoded, TypeReference<T> payloadType) {
        return some(encoded,
                enc -> new String(base64Decoder.decode(enc)),
                plain -> (T)mapper.readValue(plain, payloadType))
                .orElse(null);
    }

    private boolean verifySignature(String alg, String signature, PrivateKey pkey, String header, String payload) {
        String signAlgorithm = ALGORITHMS.getString(alg);
        if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", alg);
        if (signAlgorithm.equals("none")) {
            return true;
        }

        try {
            Signature signer = Signature.getInstance(signAlgorithm, "BC");
            signer.initSign(pkey, prng);
            signer.update(String.join(".", header, payload).getBytes());
            return Objects.equals(signature, base64Encoder.encodeToString(signer.sign()));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new UnreachableException(e);
        } catch (SignatureException e) {
            return false;
        } catch (InvalidKeyException e) {
            return false;
        }

    }

    public <T> T unsign(String message, PrivateKey pkey, TypeReference<T> typeReference) {
        String[] tokens = message.split("\\.", 3);
        if (tokens.length != 3) return null;
        try {
            JwtHeader header = mapper.readValue(base64Decoder.decode(tokens[0]), JwtHeader.class);
            if (verifySignature(header.getAlg(), tokens[2], pkey, tokens[0], tokens[1])) {
                return decodePayload(/*Payload*/tokens[1], typeReference);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public <T> T unsign(String message, PrivateKey pkey, Class<T> claimClass) {
        return unsign(message, pkey, new TypeReference<T>() {
            @Override
            public Type getType() { return claimClass; }
        });
    }

    public String sign(String payload, JwtHeader header, PrivateKey pkey) {
        String encodedHeader = encodeHeader(header);
        try {
            String signAlgorithm = ALGORITHMS.getString(header.getAlg());
            if (signAlgorithm == null) throw new MisconfigurationException("bouncr.NO_SUCH_JWT_ALGORITHM", header.getAlg());
            String encodedSignature = "";
            if (!signAlgorithm.equals("none")) {
                Signature signature = Signature.getInstance(signAlgorithm, "BC");
                signature.initSign(pkey, prng);
                signature.update(String.join(".", encodedHeader, payload).getBytes());
                encodedSignature = base64Encoder.encodeToString(signature.sign());
            }
            return String.join(".", encodedHeader, payload, encodedSignature);
        } catch (NoSuchAlgorithmException e) {
            throw new UnreachableException(e);
        } catch (SignatureException e) {
            throw new MisconfigurationException(""); //TODO
        } catch (NoSuchProviderException e) {
            throw new MisconfigurationException(""); //TODO
        } catch (InvalidKeyException e) {
            throw new MisconfigurationException(""); //TODO
        }
    }

    public String sign(Map<String, Object> claims, JwtHeader header, PrivateKey key) {
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);
    }

    public String sign(JwtClaim claims, JwtHeader header, PrivateKey key) {
        String encodedPayload = some(claims,
                p -> mapper.writeValueAsBytes(p),
                s -> base64Encoder.encodeToString(s)).orElse(null);
        return sign(encodedPayload, header, key);
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
                component.base64Encoder = Base64.getUrlEncoder();
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
