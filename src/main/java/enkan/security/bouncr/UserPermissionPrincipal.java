package enkan.security.bouncr;

import enkan.security.UserPrincipal;

import java.util.Map;
import java.util.Set;

/**
 * Authenticated principal carrying a user's numeric ID, account name, permission set,
 * and arbitrary profile attributes decoded from a Bouncr JWT.
 *
 * <p>Produced by {@link BouncrBackend#authenticate} after successful JWT verification.
 * {@link #hasPermission(String)} delegates to the {@code permissions} set for use with
 * {@link jakarta.annotation.security.RolesAllowed}-based authorization.
 */
public record UserPermissionPrincipal(
        Long id,
        String account,
        Map<String, Object> profiles,
        Set<String> permissions
) implements UserPrincipal {

    @Override
    public String getName() {
        return account;
    }

    @Override
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    public Long getId() {
        return id;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public Map<String, Object> getProfiles() {
        return profiles;
    }
}
