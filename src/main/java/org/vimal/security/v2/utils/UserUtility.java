package org.vimal.security.v2.utils;

import io.getunleash.Unleash;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.UserModel;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class UserUtility {
    public static final Set<String> MFA_METHODS = Arrays.stream(UserModel.MfaType.values()).map(e -> e.name().toLowerCase()).collect(Collectors.toSet());

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

    public static Set<String> validateInputs(RegistrationDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationUtility.validateUsername(dto.getUsername());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validatePassword(dto.getPassword());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateEmail(dto.getEmail());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateFirstName(dto.getFirstName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateMiddleName(dto.getMiddleName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateLastName(dto.getLastName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        return validationErrors;
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

    public static void validateTypeExistence(String type) {
        if (!MFA_METHODS.contains(type.toLowerCase()))
            throw new BadRequestException("Unsupported MFA type: " + type + ". Supported types: " + MFA_METHODS);
    }

    public static void checkMFAAndAuthenticatorAppMFAEnabledGlobally(Unleash unleash) {
        if (!unleash.isEnabled(FeatureFlags.MFA.name()))
            throw new ServiceUnavailableException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
    }
}
