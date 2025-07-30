package org.vimal.security.v2.utils;

import io.getunleash.Unleash;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.UserModel;

import java.util.Collection;
import java.util.Comparator;
import java.util.Objects;

public class UserUtility {
    public static Authentication getAuthenticationOfCurrentAuthenticatedUser() {
        var authentication = getAuthentication();
        if (validateAuthentication(authentication)) return authentication;
        throw new AuthenticationCredentialsNotFoundException("User not authenticated");
    }

    public static Authentication getAuthentication() {
        return SecurityContextHolder.getContext().getAuthentication();
    }

    private static boolean validateAuthentication(Authentication authentication) {
        return Objects.nonNull(authentication) && authentication.isAuthenticated() && isPrincipalInstanceOfUserDetailsImpl(authentication);
    }

    private static boolean isPrincipalInstanceOfUserDetailsImpl(Authentication authentication) {
        return isInstanceOfUserDetailsImpl(authentication.getPrincipal());
    }

    private static boolean isInstanceOfUserDetailsImpl(Object principal) {
        return principal instanceof UserDetailsImpl;
    }

    public static UserDetailsImpl getCurrentAuthenticatedUserDetails() {
        return getUserDetails(getAuthenticationOfCurrentAuthenticatedUser());
    }

    private static UserDetailsImpl getUserDetails(Authentication authentication) {
        return (UserDetailsImpl) authentication.getPrincipal();
    }

    public static UserModel getCurrentAuthenticatedUser() {
        return getCurrentAuthenticatedUserDetails().getUserModel();
    }

    private static String getUserHighestTopRole(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(SystemRoles.TOP_ROLES::contains)
                .min(Comparator.comparingInt(SystemRoles.TOP_ROLES::indexOf))
                .orElse(null);
    }

    public static String getUserHighestTopRole(UserDetailsImpl userDetails) {
        return getUserHighestTopRole(userDetails.getAuthorities());
    }

    public static boolean shouldDoMFA(UserModel user,
                                      Unleash unleash) {
        var shouldDoMFA = false;
        if (user.isMfaEnabled() && !user.getEnabledMfaMethods().isEmpty()) {
            var unleashEmailMFA = unleash.isEnabled(FeatureFlags.MFA_EMAIL.name());
            var unleashAuthenticatorAppMFA = unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name());
            if (unleashEmailMFA && user.hasMfaEnabled(UserModel.MfaType.EMAIL)) shouldDoMFA = true;
            else if (unleashAuthenticatorAppMFA && user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                shouldDoMFA = true;
        }
        return shouldDoMFA;
    }

    public static void checkMFAAndAuthenticatorAppMFAEnabledGlobally(Unleash unleash) {
        if (!unleash.isEnabled(FeatureFlags.MFA.name()))
            throw new ServiceUnavailableException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
    }
}
