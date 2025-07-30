package org.vimal.security.v2.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.utils.ArrayUtility;
import org.vimal.security.v2.utils.UserUtility;

import java.util.Set;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final String[] TOP_ROLES_ARRAY = SystemRoles.TOP_ROLES.toArray(new String[0]);
    private static final String[] CAN_CREATE_USERS_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_CREATE_USER.name());
    private static final String[] CAN_READ_USERS_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_READ_USER.name());
    private static final String[] CAN_UPDATE_USERS_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_UPDATE_USER.name());
    private static final String[] CAN_DELETE_USERS_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_DELETE_USER.name());
    private static final String[] CAN_READ_PERMISSIONS_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_READ_PERMISSION.name());
    private static final String[] CAN_CREATE_ROLES_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_CREATE_ROLE.name());
    private static final String[] CAN_READ_ROLES_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_READ_ROLE.name());
    private static final String[] CAN_UPDATE_ROLES_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_UPDATE_ROLE.name());
    private static final String[] CAN_DELETE_ROLES_ARRAY = ArrayUtility.addGivenStringToGivenStringArray(TOP_ROLES_ARRAY, SystemPermissions.CAN_DELETE_ROLE.name());

    public boolean canCreateUsers() {
        return hasAnyAuthority(CAN_CREATE_USERS_ARRAY);
    }

    public boolean canReadUsers() {
        return hasAnyAuthority(CAN_READ_USERS_ARRAY);
    }

    public boolean canUpdateUsers() {
        return hasAnyAuthority(CAN_UPDATE_USERS_ARRAY);
    }

    public boolean canDeleteUsers() {
        return hasAnyAuthority(CAN_DELETE_USERS_ARRAY);
    }

    public boolean canReadPermissions() {
        return hasAnyAuthority(CAN_READ_PERMISSIONS_ARRAY);
    }

    public boolean canCreateRoles() {
        return hasAnyAuthority(CAN_CREATE_ROLES_ARRAY);
    }

    public boolean canReadRoles() {
        return hasAnyAuthority(CAN_READ_ROLES_ARRAY);
    }

    public boolean canUpdateRoles() {
        return hasAnyAuthority(CAN_UPDATE_ROLES_ARRAY);
    }

    public boolean canDeleteRoles() {
        return hasAnyAuthority(CAN_DELETE_ROLES_ARRAY);
    }

    public boolean hasAnyAuthority(String... authorities) {
        var requiredRoles = Set.of(authorities);
        return UserUtility.getAuthenticationOfCurrentAuthenticatedUser().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(requiredRoles::contains);
    }
}
