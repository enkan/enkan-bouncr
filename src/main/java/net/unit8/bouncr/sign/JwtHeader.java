package net.unit8.bouncr.sign;

import java.io.Serializable;
import java.util.Objects;

public class JwtHeader implements Serializable {
    private String alg;
    private String kid;

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        JwtHeader jwtHeader = (JwtHeader) o;
        return Objects.equals(alg, jwtHeader.alg) &&
                Objects.equals(kid, jwtHeader.kid);
    }

    @Override
    public int hashCode() {

        return Objects.hash(alg, kid);
    }


}
