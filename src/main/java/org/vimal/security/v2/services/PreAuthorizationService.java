package org.vimal.security.v2.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.utils.UserUtility;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final Set<String> TOP_ROLES_SET = topRolesSet();
    private static final Set<String> CAN_CREATE_USERS_SET = canCreateUsersSet();
    private static final Set<String> CAN_READ_USERS_SET = canReadUsersSet();
    private static final Set<String> CAN_UPDATE_USERS_SET = canUpdateUsersSet();
    private static final Set<String> CAN_DELETE_USERS_SET = canDeleteUsersSet();
    private static final Set<String> CAN_READ_PERMISSIONS_SET = canReadPermissionsSet();
    private static final Set<String> CAN_CREATE_ROLES_SET = canCreateRolesSet();
    private static final Set<String> CAN_READ_ROLES_SET = canReadRolesSet();
    private static final Set<String> CAN_UPDATE_ROLES_SET = canUpdateRolesSet();
    private static final Set<String> CAN_DELETE_ROLES_SET = canDeleteRolesSet();

    private static Set<String> topRolesSet() {
        var set = new HashSet<>(SystemRoles.TOP_ROLES);
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateUsersSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_CREATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadUsersSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_READ_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateUsersSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_UPDATE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteUsersSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_DELETE_USER.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadPermissionsSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_READ_PERMISSION.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canCreateRolesSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_CREATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canReadRolesSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_READ_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canUpdateRolesSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_UPDATE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    private static Set<String> canDeleteRolesSet() {
        var set = new HashSet<>(TOP_ROLES_SET);
        set.add(SystemPermissions.CAN_DELETE_ROLE.name());
        return Collections.unmodifiableSet(set);
    }

    public boolean canCreateUsers() {
        return hasAnyAuthority(CAN_CREATE_USERS_SET);
    }

    public boolean canReadUsers() {
        return hasAnyAuthority(CAN_READ_USERS_SET);
    }

    public boolean canUpdateUsers() {
        return hasAnyAuthority(CAN_UPDATE_USERS_SET);
    }

    public boolean canDeleteUsers() {
        return hasAnyAuthority(CAN_DELETE_USERS_SET);
    }

    public boolean canReadPermissions() {
        return hasAnyAuthority(CAN_READ_PERMISSIONS_SET);
    }

    public boolean canCreateRoles() {
        return hasAnyAuthority(CAN_CREATE_ROLES_SET);
    }

    public boolean canReadRoles() {
        return hasAnyAuthority(CAN_READ_ROLES_SET);
    }

    public boolean canUpdateRoles() {
        return hasAnyAuthority(CAN_UPDATE_ROLES_SET);
    }

    public boolean canDeleteRoles() {
        return hasAnyAuthority(CAN_DELETE_ROLES_SET);
    }

    public boolean hasAnyAuthority(Set<String> authorities) {
        for (GrantedAuthority grantedAuthority : UserUtility.getAuthenticationOfCurrentAuthenticatedUser().getAuthorities()) {
            if (authorities.contains(grantedAuthority.getAuthority())) {
                return true;
            }
        }
        return false;
    }
}
