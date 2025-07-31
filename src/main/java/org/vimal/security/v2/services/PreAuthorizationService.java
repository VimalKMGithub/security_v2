package org.vimal.security.v2.services;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.utils.UserUtility;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service("PreAuth")
public class PreAuthorizationService {
    private static final Collection<String> TOP_ROLES_COLLECTION = Set.copyOf(SystemRoles.TOP_ROLES);
    private static final Collection<String> CAN_CREATE_USERS_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_CREATE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_READ_USERS_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_READ_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_UPDATE_USERS_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_UPDATE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_DELETE_USERS_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_DELETE_USER.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_READ_PERMISSIONS_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_READ_PERMISSION.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_CREATE_ROLES_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_CREATE_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_READ_ROLES_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_READ_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_UPDATE_ROLES_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_UPDATE_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> CAN_DELETE_ROLES_COLLECTION = Stream.concat(TOP_ROLES_COLLECTION.stream(), Stream.of(SystemPermissions.CAN_DELETE_ROLE.name())).collect(Collectors.toUnmodifiableSet());
    private static final Collection<String> TOP_TWO_ROLES_COLLECTION = Set.of(SystemRoles.TOP_ROLES.getFirst(), SystemRoles.TOP_ROLES.get(1));

    public boolean canCreateUsers() {
        return hasAnyAuthority(CAN_CREATE_USERS_COLLECTION);
    }

    public boolean canReadUsers() {
        return hasAnyAuthority(CAN_READ_USERS_COLLECTION);
    }

    public boolean canUpdateUsers() {
        return hasAnyAuthority(CAN_UPDATE_USERS_COLLECTION);
    }

    public boolean canDeleteUsers() {
        return hasAnyAuthority(CAN_DELETE_USERS_COLLECTION);
    }

    public boolean canReadPermissions() {
        return hasAnyAuthority(CAN_READ_PERMISSIONS_COLLECTION);
    }

    public boolean canCreateRoles() {
        return hasAnyAuthority(CAN_CREATE_ROLES_COLLECTION);
    }

    public boolean canReadRoles() {
        return hasAnyAuthority(CAN_READ_ROLES_COLLECTION);
    }

    public boolean canUpdateRoles() {
        return hasAnyAuthority(CAN_UPDATE_ROLES_COLLECTION);
    }

    public boolean canDeleteRoles() {
        return hasAnyAuthority(CAN_DELETE_ROLES_COLLECTION);
    }

    public boolean isTopTwoRoles() {
        return hasAnyAuthority(TOP_TWO_ROLES_COLLECTION);
    }

    public boolean hasAnyAuthority(Collection<String> authorities) {
        return UserUtility.getAuthenticationOfCurrentAuthenticatedUser().getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authorities::contains);
    }
}
