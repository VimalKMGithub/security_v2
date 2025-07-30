package org.vimal.security.v2.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.utils.UserUtility;

import java.util.Set;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final String[] TOP_ROLES_ARRAY = SystemRoles.TOP_ROLES.toArray(new String[0]);

    public boolean isInTopRoles() {
        return hasAnyAuthority(TOP_ROLES_ARRAY);
    }

    public boolean canCreateUsers() {
        return hasAnyAuthority(addPermissionToRolesArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_CREATE_USER.name()));
    }

//    public boolean canReadUsers() {
//        return hasAuthority(SystemPermissions.CAN_READ_USER.name());
//    }
//
//    public boolean canUpdateUsers() {
//        return hasAuthority(SystemPermissions.CAN_UPDATE_USER.name());
//    }
//
//    public boolean canDeleteUsers() {
//        return hasAuthority(SystemPermissions.CAN_DELETE_USER.name());
//    }
//
//    public boolean canReadPermissions() {
//        return hasAuthority(SystemPermissions.CAN_READ_PERMISSION.name());
//    }
//
//    public boolean canCreateRoles() {
//        return hasAuthority(SystemPermissions.CAN_CREATE_ROLE.name());
//    }
//
//    public boolean canReadRoles() {
//        return hasAuthority(SystemPermissions.CAN_READ_ROLE.name());
//    }
//
//    public boolean canUpdateRoles() {
//        return hasAuthority(SystemPermissions.CAN_UPDATE_ROLE.name());
//    }
//
//    public boolean canDeleteRoles() {
//        return hasAuthority(SystemPermissions.CAN_DELETE_ROLE.name());
//    }

    public boolean hasAnyAuthority(String... authorities) {
        var requiredRoles = Set.of(authorities);
        return UserUtility.getAuthenticationOfCurrentAuthenticatedUser().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(requiredRoles::contains);
    }
}
