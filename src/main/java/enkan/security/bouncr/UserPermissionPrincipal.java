package enkan.security.bouncr;

import enkan.security.UserPrincipal;

import java.util.Map;
import java.util.Set;

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
