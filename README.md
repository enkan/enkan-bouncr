# enkan-bouncr

JWT-based authentication and authorization components for the [Enkan](https://github.com/kawasima/enkan) micro-framework.

## Features

- **`JsonWebToken`** — sign and verify JWTs with HMAC (HS256/HS384/HS512), RSA/PSS (RS256/RS384/RS512, PS256/PS384/PS512), and ECDSA (ES256/ES384/ES512)
- **`BouncrBackend`** — Enkan `AuthBackend` that verifies a JWT from the `x-bouncr-credential` request header and produces a `UserPermissionPrincipal`
- **`AuthorizeControllerMethodMiddleware`** — enforces `@RolesAllowed` annotations on controller methods
- **`JwtClaim` / `ClaimAddress`** — typed beans for OIDC ID Token claims (RFC 7519 / OIDC Core)

## Requirements

- Java 21+
- BouncyCastle (`bcprov-jdk18on`, `bcpkix-jdk18on`) on the classpath for RSA/ECDSA operations

## Quick start

### 1. Register components

```java
EnkanSystem system = EnkanSystem.of(
    "jwt", new JsonWebToken(),
    "backend", new BouncrBackend()
);
((BouncrBackend) system.getComponent("backend")).setJwt(
    (JsonWebToken) system.getComponent("jwt"));
system.start();
```

### 2. Configure a verification key

#### HMAC (symmetric)

```java
BouncrBackend backend = system.getComponent("backend");
backend.setKey("your-shared-secret");   // String overload (UTF-8)
// or
backend.setKey(secretBytes);            // byte[] overload
```

#### RSA / ECDSA (asymmetric)

```java
backend.setPublicKey(publicKey);        // java.security.PublicKey
```

> Only one of `key` or `publicKey` may be set. Configuring both throws `MisconfigurationException`.

### 3. Sign a token

```java
JsonWebToken jwt = system.getComponent("jwt");

// HMAC
byte[] secret = "my-secret".getBytes(StandardCharsets.UTF_8);
String token = jwt.sign(
    Map.of("sub", "alice", "permissions", List.of("read", "write")),
    new JwtHeader("JWT", "HS256", null),
    secret
);

// RSA / ECDSA
String rsaToken = jwt.sign(claims, new JwtHeader("JWT", "RS256", null), privateKey);
```

### 4. Verify / parse a token

```java
// symmetric
Map<String, Object> claims = jwt.unsign(token, secret, new TypeReference<>() {});

// asymmetric
Map<String, Object> claims = jwt.unsign(token, publicKey, new TypeReference<>() {});
```

`unsign()` returns `null` when the signature is invalid, the token is expired, or `nbf` is not yet satisfied.

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

`alg: none` is explicitly rejected with a `MisconfigurationException`.

## Security notes

- HMAC signatures are verified with `MessageDigest.isEqual` (constant-time comparison).
- `BouncrBackend` validates the JWT `alg` header family against the configured key type before calling `unsign()`, preventing algorithm-confusion attacks.
- DER-encoded ECDSA signatures from BouncyCastle are converted to/from RFC 7518 §3.4 raw R||S format; malformed DER inputs return `null` rather than throwing.

## Building

```bash
mvn clean test
```

BouncyCastle is pulled in automatically via Maven. Production code must call
`Security.addProvider(new BouncyCastleProvider())` before the first sign/verify call
when using RSA or ECDSA algorithms.

## License

Eclipse Public License 2.0 (EPL-2.0)
