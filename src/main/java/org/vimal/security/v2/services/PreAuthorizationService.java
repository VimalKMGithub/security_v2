package org.vimal.security.v2.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.utils.UserUtility;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final Set<String> TOP_ROLES_SET = Set.copyOf(SystemRoles.TOP_ROLES);
    private static final Set<String> CAN_CREATE_USERS_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_CREATE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_READ_USERS_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_READ_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_UPDATE_USERS_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_UPDATE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_DELETE_USERS_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_DELETE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_READ_PERMISSIONS_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_READ_PERMISSION.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_CREATE_ROLES_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_CREATE_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_READ_ROLES_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_READ_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_UPDATE_ROLES_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_UPDATE_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Set<String> CAN_DELETE_ROLES_SET = Stream.concat(TOP_ROLES_SET.stream(), Stream.of(SystemPermissions.CAN_DELETE_ROLE.name())).collect(Collectors.toUnmodifiableSet());

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
