# enkan-bouncr

JWT-based authentication and authorization components for the [Enkan](https://github.com/kawasima/enkan) micro-framework.

## Features

- **`BouncrBackend`** — Enkan `AuthBackend` that verifies a JWT from the `x-bouncr-credential` request header and produces a `UserPermissionPrincipal`
- **`AuthorizeControllerMethodMiddleware`** — enforces `@RolesAllowed` annotations on controller methods
- **`JwtClaim` / `ClaimAddress`** — typed beans for OIDC ID Token claims (RFC 7519 / OIDC Core)

JWT signing and verification are provided by `enkan.web.jwt.JwtProcessor` from enkan 0.15+.

## Requirements

- Java 21+
- enkan 0.15.0+

## Quick start

### 1. Configure BouncrBackend

```java
BouncrBackend backend = new BouncrBackend();
```

#### HMAC (symmetric)

```java
backend.setKey("your-shared-secret");   // String overload (UTF-8)
// or
backend.setKey(secretBytes);            // byte[] overload
```

#### RSA / ECDSA (asymmetric)

```java
backend.setPublicKey(publicKey);        // java.security.PublicKey
```

> Only one of `key` or `publicKey` may be set. Configuring both throws `MisconfigurationException`.

### 2. Sign a token (issuer side)

Use `JwtProcessor` from enkan-web to create tokens:

```java
import enkan.web.jwt.JwtHeader;
import enkan.web.jwt.JwtProcessor;
import javax.crypto.spec.SecretKeySpec;

ObjectMapper mapper = new ObjectMapper();

// HMAC
byte[] secret = "my-secret".getBytes(StandardCharsets.UTF_8);
byte[] claimsJson = mapper.writeValueAsBytes(
    Map.of("sub", "alice", "uid", 1, "permissions", List.of("read", "write")));
String token = JwtProcessor.sign(new JwtHeader("HS256"), claimsJson,
    new SecretKeySpec(secret, "HmacSHA256"));

// RSA
byte[] claimsJson = mapper.writeValueAsBytes(claims);
String rsaToken = JwtProcessor.sign(new JwtHeader("RS256"), claimsJson, privateKey);
```

### 3. Verify a token (BouncrBackend)

`BouncrBackend` verifies tokens automatically when used as an Enkan `AuthBackend`. On success it returns a `UserPermissionPrincipal` populated from the `uid`, `sub`, and `permissions` claims.

```java
// Manual verification (without Enkan middleware stack):
import enkan.web.jwt.JwtProcessor;

byte[] payload = JwtProcessor.verify(token, publicKey);
// payload is null on failure; otherwise raw JSON bytes of the claims
```

## Supported algorithms

| JWA    | Description                        |
|--------|------------------------------------|
| HS256  | HMAC with SHA-256                  |
| HS384  | HMAC with SHA-384                  |
| HS512  | HMAC with SHA-512                  |
| RS256  | RSASSA-PKCS1-v1_5 with SHA-256     |
| RS384  | RSASSA-PKCS1-v1_5 with SHA-384     |
| RS512  | RSASSA-PKCS1-v1_5 with SHA-512     |
| PS256  | RSASSA-PSS with SHA-256            |
| PS384  | RSASSA-PSS with SHA-384            |
| PS512  | RSASSA-PSS with SHA-512            |
| ES256  | ECDSA P-256 with SHA-256           |
| ES384  | ECDSA P-384 with SHA-384           |
| ES512  | ECDSA P-521 with SHA-512           |
| EdDSA  | Ed25519                            |

`alg: none` is explicitly rejected.

## Security notes

- HMAC signatures are verified with `MessageDigest.isEqual` (constant-time comparison) inside `JwtProcessor`.
- `BouncrBackend` validates the JWT `alg` header family against the configured key type before verification, preventing algorithm-confusion attacks.
- No BouncyCastle dependency is required; standard JCA providers are used for all algorithms.

## Building

```bash
mvn clean test
```

## License

Eclipse Public License 2.0 (EPL-2.0)
