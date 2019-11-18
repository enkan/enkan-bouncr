package net.unit8.bouncr.sign;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class JwtClaim implements Serializable {
    // ID Token
    /** Issuer */
    private String iss;
    /** Subject */
    private String sub;
    /** Audience */
    private String aud;
    /** Expires*/
    private Long exp;
    /** Issued at */
    private Long iat;
    /** Auth time */
    @JsonProperty("auth_time")
    private Long AuthTime;

    private String nonce;
    /** Authentication Context Class Reference */
    private String aur;
    /** Authentication Methods Reference */
    private String amr;

    /** Authorized party*/
    private String azp;

    // Claim
    private String name;
    @JsonProperty("given_name")
    private String givenName;
    @JsonProperty("family_name")
    private String familyName;
    @JsonProperty("middle_name")
    private String middleName;
    private String nickname;
    @JsonProperty("preferred_username")
    private String preferredUsername;
    private String profile;
    private String picture;
    private String website;
    private String email;
    @JsonProperty("emailVerification")
    private Boolean emailVerification;
    private String gender;
    private String birthdate;
    private String zoneinfo;
    private String locale;
    @JsonProperty("phone_number")
    private String phoneNumber;
    @JsonProperty("phone_number_verified")
    private String phoneNumberVerified;
    private ClaimAddress address;
    @JsonProperty("updated_at")
    private LocalDateTime updatedAt;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPreferredUsername() {
        return preferredUsername;
    }

    public void setPreferredUsername(String preferredUsername) {
        this.preferredUsername = preferredUsername;
    }

    public Long getExp() {
        return exp;
    }

    public void setExp(Long exp) {
        this.exp = exp;
    }

    public Long getIat() {
        return iat;
    }

    public void setIat(Long iat) {
        this.iat = iat;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public Long getAuthTime() {
        return AuthTime;
    }

    public void setAuthTime(Long authTime) {
        AuthTime = authTime;
    }

    public String getAur() {
        return aur;
    }

    public void setAur(String aur) {
        this.aur = aur;
    }

    public String getAmr() {
        return amr;
    }

    public void setAmr(String amr) {
        this.amr = amr;
    }

    public String getAzp() {
        return azp;
    }

    public void setAzp(String azp) {
        this.azp = azp;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getMiddleName() {
        return middleName;
    }

    public void setMiddleName(String middleName) {
        this.middleName = middleName;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public Boolean getEmailVerification() {
        return emailVerification;
    }

    public void setEmailVerification(Boolean emailVerification) {
        this.emailVerification = emailVerification;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getBirthdate() {
        return birthdate;
    }

    public void setBirthdate(String birthdate) {
        this.birthdate = birthdate;
    }

    public String getZoneinfo() {
        return zoneinfo;
    }

    public void setZoneinfo(String zoneinfo) {
        this.zoneinfo = zoneinfo;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getPhoneNumberVerified() {
        return phoneNumberVerified;
    }

    public void setPhoneNumberVerified(String phoneNumberVerified) {
        this.phoneNumberVerified = phoneNumberVerified;
    }

    public ClaimAddress getAddress() {
        return address;
    }

    public void setAddress(ClaimAddress address) {
        this.address = address;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
