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
import java.util.Objects;

public class UserUtility {
    public static Authentication getAuthenticationOfCurrentAuthenticatedUser() {
        var authentication = getAuthentication();
        if (checkAuthentication(authentication)) return authentication;
        throw new AuthenticationCredentialsNotFoundException("User not authenticated");
    }

    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    public static boolean checkAuthentication(Authentication authentication) {
        return Objects.nonNull(authentication) && authentication.isAuthenticated() && isPrincipalInstanceOfUserDetailsImpl(authentication);
    }

    public static boolean isPrincipalInstanceOfUserDetailsImpl(Authentication authentication) {
        return isInstanceOfUserDetailsImpl(authentication.getPrincipal());
    }

    public static boolean isInstanceOfUserDetailsImpl(Object principal) {
        return principal instanceof UserDetailsImpl;
    }

    public static UserDetailsImpl getCurrentAuthenticatedUserDetails() {
        return getUserDetails(getAuthenticationOfCurrentAuthenticatedUser());
    }

    public static UserDetailsImpl getUserDetails(Authentication authentication) {
        return (UserDetailsImpl) authentication.getPrincipal();
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
