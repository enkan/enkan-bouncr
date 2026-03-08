package net.unit8.bouncr.sign;

import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class JwtClaimSerializationTest {

    private JsonMapper mapper;

    @BeforeEach
    public void setup() {
        mapper = JsonMapper.builder().build();
    }

    // --- serialization ---

    @Test
    public void serializesStandardClaims() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setSub("kawasima");
        claim.setIss("https://example.com");
        claim.setAud("myapp");
        claim.setExp(9999999999L);
        claim.setIat(1000000000L);

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"sub\":\"kawasima\"");
        assertThat(json).contains("\"iss\":\"https://example.com\"");
        assertThat(json).contains("\"aud\":\"myapp\"");
        assertThat(json).contains("\"exp\":9999999999");
        assertThat(json).contains("\"iat\":1000000000");
    }

    @Test
    public void nullFieldsAreOmittedDueToJsonInclude() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setSub("kawasima");
        // all other fields are null

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"sub\"");
        assertThat(json).doesNotContain("\"iss\"");
        assertThat(json).doesNotContain("\"email\"");
        assertThat(json).doesNotContain("\"given_name\"");
    }

    @Test
    public void serializesSnakeCaseProperties() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setGivenName("Yoshitaka");
        claim.setFamilyName("Kawashima");
        claim.setPhoneNumber("+81-90-1234-5678");
        claim.setPreferredUsername("kawasima");

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"given_name\":\"Yoshitaka\"");
        assertThat(json).contains("\"family_name\":\"Kawashima\"");
        assertThat(json).contains("\"phone_number\":\"+81-90-1234-5678\"");
        assertThat(json).contains("\"preferred_username\":\"kawasima\"");
    }

    @Test
    public void serializesEmailVerifiedAsEmailVerified() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setEmailVerified(true);

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"email_verified\":true");
    }

    @Test
    public void serializesPhoneNumberVerifiedAsBoolean() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setPhoneNumberVerified(true);

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"phone_number_verified\":true");
    }

    @Test
    public void serializesAuthTime() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setAuthTime(1700000000L);

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"auth_time\":1700000000");
    }

    @Test
    public void serializesAcr() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setAcr("urn:mace:incommon:iap:bronze");

        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"acr\":\"urn:mace:incommon:iap:bronze\"");
    }

    // --- deserialization ---

    @Test
    public void deserializesStandardClaims() throws Exception {
        String json = "{\"sub\":\"kawasima\",\"iss\":\"https://example.com\",\"exp\":9999999999}";
        JwtClaim claim = mapper.readValue(json, JwtClaim.class);
        assertThat(claim.getSub()).isEqualTo("kawasima");
        assertThat(claim.getIss()).isEqualTo("https://example.com");
        assertThat(claim.getExp()).isEqualTo(9999999999L);
    }

    @Test
    public void deserializesSnakeCaseProperties() throws Exception {
        String json = "{\"given_name\":\"Yoshitaka\",\"family_name\":\"Kawashima\","
                + "\"phone_number\":\"+81-90-0000-0000\",\"preferred_username\":\"kawasima\"}";
        JwtClaim claim = mapper.readValue(json, JwtClaim.class);
        assertThat(claim.getGivenName()).isEqualTo("Yoshitaka");
        assertThat(claim.getFamilyName()).isEqualTo("Kawashima");
        assertThat(claim.getPhoneNumber()).isEqualTo("+81-90-0000-0000");
        assertThat(claim.getPreferredUsername()).isEqualTo("kawasima");
    }

    @Test
    public void deserializesEmailVerified() throws Exception {
        JwtClaim claim = mapper.readValue("{\"email_verified\":true}", JwtClaim.class);
        assertThat(claim.getEmailVerified()).isTrue();
    }

    @Test
    public void deserializesPhoneNumberVerified() throws Exception {
        JwtClaim claim = mapper.readValue("{\"phone_number_verified\":false}", JwtClaim.class);
        assertThat(claim.getPhoneNumberVerified()).isFalse();
    }

    @Test
    public void deserializesAuthTime() throws Exception {
        JwtClaim claim = mapper.readValue("{\"auth_time\":1700000000}", JwtClaim.class);
        assertThat(claim.getAuthTime()).isEqualTo(1700000000L);
    }

    @Test
    public void deserializesAcr() throws Exception {
        JwtClaim claim = mapper.readValue("{\"acr\":\"urn:mace:incommon:iap:bronze\"}", JwtClaim.class);
        assertThat(claim.getAcr()).isEqualTo("urn:mace:incommon:iap:bronze");
    }

    @Test
    public void deserializesNestedAddress() throws Exception {
        String json = "{\"address\":{\"formatted\":\"Tokyo Japan\",\"street_address\":\"1-1 Chiyoda\","
                + "\"locality\":\"Chiyoda-ku\",\"region\":\"Tokyo\",\"postal_code\":\"100-0001\",\"country\":\"JP\"}}";
        JwtClaim claim = mapper.readValue(json, JwtClaim.class);
        ClaimAddress addr = claim.getAddress();
        assertThat(addr.getFormatted()).isEqualTo("Tokyo Japan");
        assertThat(addr.getStreetAddress()).isEqualTo("1-1 Chiyoda");
        assertThat(addr.getLocality()).isEqualTo("Chiyoda-ku");
        assertThat(addr.getRegion()).isEqualTo("Tokyo");
        assertThat(addr.getPostalCode()).isEqualTo("100-0001");
        assertThat(addr.getCountry()).isEqualTo("JP");
    }

    @Test
    public void unknownPropertiesAreIgnored() throws Exception {
        String json = "{\"sub\":\"kawasima\",\"unknown_future_claim\":\"value\"}";
        JwtClaim claim = mapper.readValue(json, JwtClaim.class);
        assertThat(claim.getSub()).isEqualTo("kawasima");
    }

    // --- aud (RFC 7519 §4.1.3): single string or array ---

    @Test
    public void serializesAudAsString() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setAud("myapp");
        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"aud\":\"myapp\"");
    }

    @Test
    public void serializesAudAsArray() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setAud(List.of("app1", "app2"));
        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"aud\":[\"app1\",\"app2\"]");
    }

    @Test
    public void deserializesAudAsString() throws Exception {
        JwtClaim claim = mapper.readValue("{\"aud\":\"myapp\"}", JwtClaim.class);
        assertThat(claim.getAud()).isEqualTo("myapp");
    }

    @Test
    public void deserializesAudAsArray() throws Exception {
        JwtClaim claim = mapper.readValue("{\"aud\":[\"app1\",\"app2\"]}", JwtClaim.class);
        assertThat(claim.getAud()).isInstanceOf(List.class);
    }

    // --- amr (OIDC Core §2): array of strings, accepts single string ---

    @Test
    public void serializesAmrAsArray() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setAmr(List.of("pwd", "otp"));
        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"amr\":[\"pwd\",\"otp\"]");
    }

    @Test
    public void deserializesAmrAsArray() throws Exception {
        JwtClaim claim = mapper.readValue("{\"amr\":[\"pwd\",\"otp\"]}", JwtClaim.class);
        assertThat(claim.getAmr()).containsExactly("pwd", "otp");
    }

    // --- updated_at (OIDC Core §5.1): NumericDate as Long ---

    @Test
    public void serializesUpdatedAtAsNumber() throws Exception {
        JwtClaim claim = new JwtClaim();
        claim.setUpdatedAt(1700000000L);
        String json = mapper.writeValueAsString(claim);
        assertThat(json).contains("\"updated_at\":1700000000");
    }

    @Test
    public void deserializesUpdatedAtAsNumber() throws Exception {
        JwtClaim claim = mapper.readValue("{\"updated_at\":1700000000}", JwtClaim.class);
        assertThat(claim.getUpdatedAt()).isEqualTo(1700000000L);
    }

    // --- JwtHeader equals/hashCode ---

    @Test
    public void jwtHeaderEqualsAndHashCode() {
        JwtHeader h1 = new JwtHeader(null, "RS256", "key-1");
        JwtHeader h2 = new JwtHeader(null, "RS256", "key-1");
        JwtHeader h3 = new JwtHeader(null, "HS256", "key-1");

        assertThat(h1).isEqualTo(h2);
        assertThat(h1.hashCode()).isEqualTo(h2.hashCode());
        assertThat(h1).isNotEqualTo(h3);
    }

    @Test
    public void jwtHeaderNullFieldsEquality() {
        JwtHeader h1 = new JwtHeader(null, "RS256", null);
        JwtHeader h2 = new JwtHeader(null, "RS256", null);

        assertThat(h1).isEqualTo(h2);
        assertThat(h1).isNotEqualTo(null);
    }
}
