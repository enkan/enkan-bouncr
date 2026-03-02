package enkan.security.bouncr;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class UserPermissionPrincipalTest {

    private UserPermissionPrincipal principal(Set<String> permissions) {
        return new UserPermissionPrincipal(1L, "kawasima", Map.of("email", "test@example.com"), permissions);
    }

    @Test
    public void getId() {
        UserPermissionPrincipal p = new UserPermissionPrincipal(42L, "user", Map.of(), Set.of());
        assertThat(p.getId()).isEqualTo(42L);
    }

    @Test
    public void getName() {
        UserPermissionPrincipal p = new UserPermissionPrincipal(1L, "kawasima", Map.of(), Set.of());
        assertThat(p.getName()).isEqualTo("kawasima");
    }

    @Test
    public void hasPermissionReturnsTrueWhenPresent() {
        UserPermissionPrincipal p = principal(Set.of("read", "write"));
        assertThat(p.hasPermission("read")).isTrue();
        assertThat(p.hasPermission("write")).isTrue();
    }

    @Test
    public void hasPermissionReturnsFalseWhenAbsent() {
        UserPermissionPrincipal p = principal(Set.of("read"));
        assertThat(p.hasPermission("delete")).isFalse();
    }

    @Test
    public void hasPermissionIsCaseSensitive() {
        UserPermissionPrincipal p = principal(Set.of("Read"));
        assertThat(p.hasPermission("read")).isFalse();
        assertThat(p.hasPermission("Read")).isTrue();
    }

    @Test
    public void hasPermissionWithEmptySet() {
        UserPermissionPrincipal p = principal(Set.of());
        assertThat(p.hasPermission("anything")).isFalse();
    }

    @Test
    public void getPermissions() {
        Set<String> perms = Set.of("read", "write");
        UserPermissionPrincipal p = principal(perms);
        assertThat(p.getPermissions()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    public void getProfiles() {
        Map<String, Object> profiles = new HashMap<>();
        profiles.put("email", "test@example.com");
        profiles.put("locale", "ja");
        UserPermissionPrincipal p = new UserPermissionPrincipal(1L, "user", profiles, Set.of());
        assertThat(p.getProfiles()).containsEntry("email", "test@example.com");
        assertThat(p.getProfiles()).containsEntry("locale", "ja");
    }

    @Test
    public void nullIdIsAllowed() {
        UserPermissionPrincipal p = new UserPermissionPrincipal(null, "user", Map.of(), Set.of());
        assertThat(p.getId()).isNull();
    }
}
