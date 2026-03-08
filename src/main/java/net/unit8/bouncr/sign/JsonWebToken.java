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
import java.security.interfaces.ECKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

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

    /**
     * Decodes the JOSE header from a JWT token string without verifying the signature.
     * Returns null if the token is malformed or the header cannot be parsed.
     */
    public JwtHeader decodeHeader(String token) {
        if (token == null || mapper == null) return null;
        String[] parts = token.split("\\.", 3);
        if (parts.length < 2) return null;
        try {
            return mapper.readValue(base64Decoder.decode(parts[0]), JwtHeader.class);
        } catch (Exception e) {
            return null;
        }
    }

    public <T> T decodePayload(String encoded, TypeReference<T> payloadType) {
        requireStarted();
        return some(encoded,
                enc -> new String(base64Decoder.decode(enc)),
                plain -> (T) mapper.readValue(plain, payloadType))
                .orElse(null);
    }

    /**
     * Converts a DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s }) to the
     * raw R||S concatenation format required by RFC 7518 §3.4 (JWS ECDSA).
     * Each component is zero-padded to the expected length (keyBits/8 bytes, rounded up).
     */
    private byte[] derToP1363(byte[] der, int keyBits) {
        int componentLen = (keyBits + 7) / 8;
        // Parse DER: 0x30 <len> 0x02 <r-len> <r> 0x02 <s-len> <s>
        // Length may be long-form: 0x81 <1-byte-len> for lengths >= 128
        if (der == null || der.length < 8) return null;
        int pos = 1; // skip SEQUENCE tag (0x30)
        int seqLenByte = der[pos++] & 0xff;
        if ((seqLenByte & 0x80) != 0) {
            int lenLen = seqLenByte & 0x7f;
            if (pos + lenLen > der.length) return null;
            pos += lenLen; // skip multi-byte length
        }
        if (pos + 2 > der.length) return null;
        pos++; // skip INTEGER tag for r
        int rLen = der[pos++] & 0xff;
        if (pos + rLen + 2 > der.length) return null;
        byte[] r = java.util.Arrays.copyOfRange(der, pos, pos + rLen);
        pos += rLen;
        pos++; // skip INTEGER tag for s
        if (pos >= der.length) return null;
        int sLen = der[pos++] & 0xff;
        if (pos + sLen > der.length) return null;
        byte[] s = java.util.Arrays.copyOfRange(der, pos, pos + sLen);

        byte[] result = new byte[componentLen * 2];
        // Copy r right-aligned, stripping any leading 0x00 padding byte
        int rStart = r.length > componentLen ? r.length - componentLen : 0;
        int rDest = componentLen - (r.length - rStart);
        System.arraycopy(r, rStart, result, rDest, r.length - rStart);
        // Copy s right-aligned
        int sStart = s.length > componentLen ? s.length - componentLen : 0;
        int sDest = componentLen * 2 - (s.length - sStart);
        System.arraycopy(s, sStart, result, sDest, s.length - sStart);
        return result;
    }

    /**
     * Converts a raw R||S ECDSA signature (RFC 7518 §3.4) to DER encoding for BouncyCastle verification.
     * Returns null if the input is null, empty, or has odd length.
     * Handles DER long-form length encoding for sequences longer than 127 bytes (e.g. ES512/P-521).
     */
    private byte[] p1363ToDer(byte[] p1363) {
        if (p1363 == null || p1363.length == 0 || (p1363.length % 2) != 0) {
            return null;
        }
        int componentLen = p1363.length / 2;
        byte[] r = java.util.Arrays.copyOfRange(p1363, 0, componentLen);
        byte[] s = java.util.Arrays.copyOfRange(p1363, componentLen, p1363.length);
        // Strip leading 0x00 bytes for minimal DER encoding, leaving at least one byte
        r = stripLeadingZeros(r);
        s = stripLeadingZeros(s);
        // Prepend 0x00 if high bit is set to keep the integer positive in DER
        byte[] rDer = r[0] < 0 ? prependZero(r) : r;
        byte[] sDer = s[0] < 0 ? prependZero(s) : s;
        int contentLen = 2 + rDer.length + 2 + sDer.length;
        // Use long-form length encoding when contentLen > 127 (required for ES512/P-521)
        byte[] lenBytes = contentLen > 127
                ? new byte[]{(byte) 0x81, (byte) contentLen}
                : new byte[]{(byte) contentLen};
        byte[] der = new byte[1 + lenBytes.length + contentLen];
        int i = 0;
        der[i++] = 0x30;
        System.arraycopy(lenBytes, 0, der, i, lenBytes.length);
        i += lenBytes.length;
        der[i++] = 0x02;
        der[i++] = (byte) rDer.length;
        System.arraycopy(rDer, 0, der, i, rDer.length);
        i += rDer.length;
        der[i++] = 0x02;
        der[i++] = (byte) sDer.length;
        System.arraycopy(sDer, 0, der, i, sDer.length);
        return der;
    }

    private byte[] prependZero(byte[] b) {
        byte[] r = new byte[b.length + 1];
        System.arraycopy(b, 0, r, 1, b.length);
        return r;
    }

    private byte[] stripLeadingZeros(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) i++;
        return i == 0 ? b : java.util.Arrays.copyOfRange(b, i, b.length);
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
            throw new IllegalArgumentException("Non-numeric or non-integer time claim", e);
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
                Mac mac = Mac.getInstance(signAlgorithm);
                mac.init(keySpec);
                mac.update(String.join(".", header, payload).getBytes(StandardCharsets.US_ASCII));
                byte[] expected = mac.doFinal();
                byte[] provided;
                try {
                    provided = base64Decoder.decode(signature);
                } catch (IllegalArgumentException e) {
                    return false;
                }
                return MessageDigest.isEqual(expected, provided);
            } else {
                boolean isEcdsa = signAlgorithm.contains("ECDSA");
                Signature verifier = Signature.getInstance(signAlgorithm, "BC");
                String keyAlg = isEcdsa ? "EC" : "RSA";
                KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
                PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(key));
                verifier.initVerify(publicKey);
                verifier.update(String.join(".", header, payload).getBytes(StandardCharsets.US_ASCII));
                // Convert JWS raw R||S to DER for BouncyCastle verification (RFC 7518 §3.4)
                byte[] sigBytes;
                try {
                    sigBytes = base64Decoder.decode(signature);
                } catch (IllegalArgumentException e) {
                    return false;
                }
                if (isEcdsa) {
                    // Validate RFC 7518 §3.4 P1363 length before conversion
                    int expectedLen = alg.equals("ES256") ? 64 : alg.equals("ES384") ? 96 : alg.equals("ES512") ? 132 : -1;
                    if (sigBytes.length == 0 || (sigBytes.length % 2) != 0
                            || (expectedLen > 0 && sigBytes.length != expectedLen)) {
                        return false;
                    }
                    byte[] derSig = p1363ToDer(sigBytes);
                    if (derSig == null) return false;
                    return verifier.verify(derSig);
                }
                return verifier.verify(sigBytes);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnreachableException(e);
        } catch (NoSuchProviderException e) {
            throw new MisconfigurationException("bouncr.NO_SUCH_CRYPTO_PROVIDER",
                    "BouncyCastle provider is not registered. Add Security.addProvider(new BouncyCastleProvider()).");
        } catch (SignatureException | InvalidKeyException | InvalidKeySpecException e) {
            return false;
        }

    }

    public <T> T unsign(String message, byte[] key, TypeReference<T> typeReference) {
        requireStarted();
        String[] tokens = message.split("\\.", 3);
        if (tokens.length != 3) return null;
        JwtHeader header;
        try {
            header = mapper.readValue(base64Decoder.decode(tokens[0]), JwtHeader.class);
        } catch (Exception e) {
            return null;
        }
        if (header == null || header.alg() == null) return null;
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
                boolean isEcdsa = signAlgorithm.contains("ECDSA");
                Signature signature = Signature.getInstance(signAlgorithm, "BC");
                String keyAlg = isEcdsa ? "EC" : "RSA";
                KeyFactory kf = KeyFactory.getInstance(keyAlg, "BC");
                PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(key));
                signature.initSign(privateKey, prng);
                signature.update(String.join(".", encodedHeader, payload).getBytes(StandardCharsets.US_ASCII));
                byte[] rawSig = signature.sign();
                if (isEcdsa) {
                    // Derive key length from the actual EC key to avoid alg/key mismatch
                    int keyBits = ((ECKey) privateKey).getParams().getOrder().bitLength();
                    // Validate that the EC key size (bit length) matches the declared JWA algorithm
                    int expectedKeyBits = header.alg().equals("ES256") ? 256
                            : header.alg().equals("ES384") ? 384
                            : header.alg().equals("ES512") ? 521 : -1;
                    if (expectedKeyBits > 0 && keyBits != expectedKeyBits) {
                        throw new MisconfigurationException("bouncr.ECDSA_KEY_ALG_MISMATCH",
                                "EC key size (" + keyBits + " bits) does not match algorithm " + header.alg());
                    }
                    rawSig = derToP1363(rawSig, keyBits);
                }
                encodedSignature = base64Encoder.encodeToString(rawSig);
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
