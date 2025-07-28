package org.vimal.security.v2.utils;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.UserModel;

import java.util.Collection;
import java.util.Comparator;

public class UserUtility {
    public static Authentication getAuthenticationOfCurrentAuthenticatedUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof UserDetailsImpl))
            throw new AuthenticationCredentialsNotFoundException("User not authenticated");
        return authentication;
    }

    public static UserDetailsImpl getCurrentAuthenticatedUserDetails() {
        return (UserDetailsImpl) getAuthenticationOfCurrentAuthenticatedUser().getPrincipal();
    }

    public static UserModel getCurrentAuthenticatedUser() {
        return getCurrentAuthenticatedUserDetails().getUserModel();
    }

    public static String getCurrentAuthenticatedUserHighestTopRole() {
        return getUserHighestTopRole(getAuthenticationOfCurrentAuthenticatedUser().getAuthorities());
    }

    public static String getUserHighestTopRole(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(SystemRoles.TOP_ROLES::contains)
                .min(Comparator.comparingInt(SystemRoles.TOP_ROLES::indexOf))
                .orElse(null);
    }

    public static String getUserHighestTopRole(UserDetailsImpl userDetails) {
        return getUserHighestTopRole(userDetails.getAuthorities());
    }

    public static String getUserHighestTopRole(Authentication authentication) {
        return getUserHighestTopRole(authentication.getAuthorities());
    }
}
