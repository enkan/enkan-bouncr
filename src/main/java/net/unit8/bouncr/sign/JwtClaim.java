package net.unit8.bouncr.sign;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Objects;

public class JwtClaim implements Serializable {
    private String email;
    private String picture;
    private String sub;
    private String iss;
    private String aud;
    private String name;
    @JsonProperty("preferred_username")
    private String preferredUsername;
    private Long exp;
    private Long iat;
    private String nonce;

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwtClaim jwtClaim = (JwtClaim) o;
        return Objects.equals(email, jwtClaim.email) &&
                Objects.equals(picture, jwtClaim.picture) &&
                Objects.equals(sub, jwtClaim.sub) &&
                Objects.equals(iss, jwtClaim.iss) &&
                Objects.equals(aud, jwtClaim.aud) &&
                Objects.equals(name, jwtClaim.name) &&
                Objects.equals(preferredUsername, jwtClaim.preferredUsername) &&
                Objects.equals(exp, jwtClaim.exp) &&
                Objects.equals(iat, jwtClaim.iat) &&
                Objects.equals(nonce, jwtClaim.nonce);
    }

    @Override
    public int hashCode() {

        return Objects.hash(email, picture, sub, iss, aud, name, preferredUsername, exp, iat, nonce);
    }

    @Override
    public String toString() {
        return "JwtClaim{" +
                "email='" + email + '\'' +
                ", picture='" + picture + '\'' +
                ", sub='" + sub + '\'' +
                ", iss='" + iss + '\'' +
                ", aud='" + aud + '\'' +
                ", name='" + name + '\'' +
                ", preferredUsername='" + preferredUsername + '\'' +
                ", exp=" + exp +
                ", iat=" + iat +
                ", nonce='" + nonce + '\'' +
                '}';
    }
}
