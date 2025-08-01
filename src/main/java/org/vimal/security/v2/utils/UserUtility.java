package org.vimal.security.v2.utils;

import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.UserModel;

import java.util.Collection;
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

    public static boolean entryCheck(Variant variant,
                                     String userHighestTopRole) {
        return variant.isEnabled() || SystemRoles.TOP_ROLES.getFirst().equals(userHighestTopRole);
    }

    public static void checkUserCanCreateUsers(String userHighestTopRole,
                                               Unleash unleash) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name()))
            throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    public static void validateDtosSizeForUsersCreation(Variant variant,
                                                        Collection<?> dtos,
                                                        int min,
                                                        int max) {
        if (dtos.isEmpty()) throw new BadRequestException("No users to create");
        if (dtos.size() < min) throw new BadRequestException("At least " + min + " users must be created at a time");
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            var maxUsersToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToCreateAtATime < 1) maxUsersToCreateAtATime = max;
            if (dtos.size() > maxUsersToCreateAtATime)
                throw new BadRequestException("Cannot create more than " + maxUsersToCreateAtATime + " users at a time");
        } else if (dtos.size() > max)
            throw new BadRequestException("Cannot create more than " + max + " users at a time");
    }
}
