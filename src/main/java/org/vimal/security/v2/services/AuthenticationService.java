package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.converter.*;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private static final Set<String> TOGGLE_TYPE = Set.of("enable", "disable");
    private static final String STATE_TOKEN_PREFIX = "SECURITY_V2_STATE_TOKEN:";
    private static final String STATE_TOKEN_MAPPING_PREFIX = "SECURITY_V2_STATE_TOKEN_MAPPING:";
    private static final String EMAIL_MFA_OTP_PREFIX = "SECURITY_V2_EMAIL_MFA_OTP:";
    private static final String AUTHENTICATOR_APP_SECRET_PREFIX = "SECURITY_V2_AUTHENTICATOR_APP_SECRET:";
    private final AuthenticationManager authenticationManager;
    private final JWTUtility jwtUtility;
    private final RedisService redisService;
    private final UserRepo userRepo;
    private final MailService mailService;
    private final Unleash unleash;
    private final StateTokenStaticConverter stateTokenStaticConverter;
    private final StateTokenRandomConverter stateTokenRandomConverter;
    private final EmailOTPStaticConverter emailOTPStaticConverter;
    private final EmailOTPRandomConverter emailOTPRandomConverter;
    private final AuthenticatorAppMFASecretStaticConverter authenticatorAppMFASecretStaticConverter;
    private final AuthenticatorAppMFASecretRandomConverter authenticatorAppMFASecretRandomConverter;
    private final AuthenticatorAppSecretRandomConverter authenticatorAppSecretRandomConverter;

    public Map<String, Object> login(String usernameOrEmail,
                                     String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateStringNonNullAndNotEmpty(usernameOrEmail, "Username/email");
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        UserModel user;
        if (ValidationUtility.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            user = userRepo.findByEmail(usernameOrEmail).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        else if (ValidationUtility.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            user = userRepo.findByUsername(usernameOrEmail).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        else throw new BadCredentialsException("Invalid credentials");
        return proceedLogin(user, password);
    }

    private Map<String, Object> proceedLogin(UserModel user,
                                             String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), password));
            return handleSuccessfulLogin(user);
        } catch (BadCredentialsException ex) {
            if (ex.getCause() instanceof UsernameNotFoundException) throw ex;
            handleFailedLogin(user);
            throw ex;
        }
    }

    private Map<String, Object> handleSuccessfulLogin(UserModel user) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.MFA.name())) {
            if (UserUtility.shouldDoMFA(user, unleash))
                return Map.of("message", "MFA required", "state_token", generateStateToken(user), "mfa_methods", user.getEnabledMfaMethods());
            if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                return Map.of("message", "MFA required", "state_token", generateStateToken(user), "mfa_methods", Set.of(UserModel.MfaType.EMAIL));
        }
        return jwtUtility.generateTokens(user);
    }

    private UUID generateStateToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedStateTokenKey = getEncryptedStateTokenKey(user);
        var existingEncryptedStateToken = redisService.get(encryptedStateTokenKey);
        if (existingEncryptedStateToken != null)
            return stateTokenRandomConverter.decrypt((String) existingEncryptedStateToken, UUID.class);
        var stateToken = UUID.randomUUID();
        var encryptedStateTokenMappingKey = stateTokenStaticConverter.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
        try {
            redisService.save(encryptedStateTokenKey, stateTokenRandomConverter.encrypt(stateToken), RedisService.DEFAULT_TTL);
            redisService.save(encryptedStateTokenMappingKey, stateTokenRandomConverter.encrypt(user.getId()), RedisService.DEFAULT_TTL);
            return stateToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedStateTokenKey, encryptedStateTokenMappingKey));
            throw new RuntimeException("Failed to generate state token", ex);
        }
    }

    private String getEncryptedStateTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return stateTokenStaticConverter.encrypt(STATE_TOKEN_PREFIX + user.getId());
    }

    private void handleFailedLogin(UserModel user) {
        user.recordFailedLoginAttempt();
        userRepo.save(user);
    }

    public Map<String, String> logout() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUser();
        jwtUtility.revokeTokens(user);
        return Map.of("message", "Logout successful");
    }

    public Map<String, Object> refreshAccessToken(String refreshToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateUuid(refreshToken, "Refresh token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid refresh token");
        }
        return jwtUtility.refreshAccessToken(refreshToken);
    }

    public Map<String, String> revokeAccessToken() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        jwtUtility.revokeAccessToken(UserUtility.getCurrentAuthenticatedUser());
        return Map.of("message", "Access token revoked successfully");
    }

    public Map<String, String> revokeRefreshToken(String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateUuid(refreshToken, "Refresh token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid refresh token");
        }
        jwtUtility.revokeRefreshToken(refreshToken);
        return Map.of("message", "Refresh token revoked successfully");
    }

    public ResponseEntity<Object> requestToToggleMFA(String type,
                                                     String toggle) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        var toggleEnabled = validateToggle(toggle);
        var user = UserUtility.getCurrentAuthenticatedUser();
        return proceedRequestToToggleMFA(user, validateType(type, user, toggleEnabled), toggleEnabled);
    }

    private boolean validateToggle(String toggle) {
        if (!TOGGLE_TYPE.contains(toggle.toLowerCase()))
            throw new BadRequestException("Unsupported toggle type: " + toggle + ". Supported values: " + TOGGLE_TYPE);
        return toggle.equalsIgnoreCase("enable");
    }

    private UserModel.MfaType validateType(String type,
                                           UserModel user,
                                           boolean toggleEnabled) {
        UserUtility.validateTypeExistence(type);
        UserUtility.checkMFAEnabledGlobally(unleash);
        var mfaType = UserModel.MfaType.valueOf(type.toUpperCase());
        if (!unleash.isEnabled(mfaType.getFeatureFlag().name()))
            throw new ServiceUnavailableException(type + " MFA is disabled globally");
        var hasMFAType = user.hasMfaEnabled(mfaType);
        if (toggleEnabled && hasMFAType) throw new BadRequestException(type + " MFA is already enabled");
        if (!toggleEnabled && !hasMFAType) throw new BadRequestException(type + " MFA is already disabled");
        return mfaType;
    }

    private ResponseEntity<Object> proceedRequestToToggleMFA(UserModel user,
                                                             UserModel.MfaType type,
                                                             boolean toggleEnabled) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        if (toggleEnabled) {
            switch (type) {
                case UserModel.MfaType.EMAIL -> {
                    mailService.sendEmailAsync(user.getEmail(), "OTP to enable email MFA", generateOTPForEmailMFA(user), MailService.MailType.OTP);
                    return ResponseEntity.ok(Map.of("message", "OTP sent to your registered email address. Please check your email to continue"));
                }
                case UserModel.MfaType.AUTHENTICATOR_APP -> {
                    return ResponseEntity.ok().contentType(MediaType.IMAGE_PNG).body(generateQRCodeForAuthenticatorApp(user));
                }
            }
        } else {
            switch (type) {
                case UserModel.MfaType.EMAIL -> {
                    mailService.sendEmailAsync(user.getEmail(), "OTP to disable email MFA", generateOTPForEmailMFA(user), MailService.MailType.OTP);
                    return ResponseEntity.ok(Map.of("message", "OTP sent to your registered email address. Please check your email to continue"));
                }
                case UserModel.MfaType.AUTHENTICATOR_APP -> {
                    return ResponseEntity.ok(Map.of("message", "Please proceed to verify TOTP"));
                }
            }
        }
        throw new BadRequestException("Unsupported MFA type: " + type + ". Supported types: " + UserUtility.MFA_METHODS);
    }

    private String generateOTPForEmailMFA(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedEmailMFAOTPKey(user), emailOTPRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedEmailMFAOTPKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPStaticConverter.encrypt(EMAIL_MFA_OTP_PREFIX + user.getId());
    }

    private byte[] generateQRCodeForAuthenticatorApp(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        return QRUtility.generateQRCode(TOTPUtility.generateTOTPUrl("God Level Security", user.getUsername(), generateAuthenticatorAppSecret(user)));
    }

    private String generateAuthenticatorAppSecret(UserModel user) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var secret = TOTPUtility.generateBase32Secret();
        redisService.save(getEncryptedSecretKey(user), authenticatorAppMFASecretRandomConverter.encrypt(secret), RedisService.DEFAULT_TTL);
        return secret;
    }

    private String getEncryptedSecretKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return authenticatorAppMFASecretStaticConverter.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + user.getId());
    }

    public Map<String, String> verifyToggleMFA(String type,
                                               String toggle,
                                               String otpTotp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var toggleEnabled = validateToggle(toggle);
        var user = UserUtility.getCurrentAuthenticatedUser();
        return proceedToVerifyToggleMFA(user, validateType(type, user, toggleEnabled), toggleEnabled, otpTotp);
    }

    private Map<String, String> proceedToVerifyToggleMFA(UserModel user,
                                                         UserModel.MfaType type,
                                                         boolean toggleEnabled,
                                                         String otpTotp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (toggleEnabled) {
            switch (type) {
                case UserModel.MfaType.EMAIL -> {
                    return verifyOTPToToggleEmailMFA(user, otpTotp, true);
                }
                case UserModel.MfaType.AUTHENTICATOR_APP -> {
                    return verifyTOTPToEnableAuthenticatorApp(user, otpTotp);
                }
            }
        } else {
            switch (type) {
                case UserModel.MfaType.EMAIL -> {
                    return verifyOTPToToggleEmailMFA(user, otpTotp, false);
                }
                case UserModel.MfaType.AUTHENTICATOR_APP -> {
                    return verifyTOTPToDisableAuthenticatorAppMFA(user, otpTotp);
                }
            }
        }
        throw new BadRequestException("Unsupported MFA type: " + type + ". Supported types: " + UserUtility.MFA_METHODS);
    }

    private Map<String, String> verifyOTPToToggleEmailMFA(UserModel user,
                                                          String otp,
                                                          boolean toggle) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateOTPTOTP(otp);
        var encryptedEmailMFAOTPKey = getEncryptedEmailMFAOTPKey(user);
        var encryptedOTP = redisService.get(encryptedEmailMFAOTPKey);
        if (encryptedOTP != null) {
            if (emailOTPRandomConverter.decrypt((String) encryptedOTP, String.class).equals(otp)) {
                try {
                    redisService.delete(encryptedEmailMFAOTPKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
                if (toggle) user.enableMfaMethod(UserModel.MfaType.EMAIL);
                else user.disableMfaMethod(UserModel.MfaType.EMAIL);
                user.setUpdatedBy("SELF");
                jwtUtility.revokeTokens(user);
                userRepo.save(user);
                emailConfirmationOnToggleMFA(user, UserModel.MfaType.EMAIL, toggle);
                if (toggle) return Map.of("message", "Email MFA enabled successfully. Please log in again to continue");
                else return Map.of("message", "Email MFA disabled successfully. Please log in again to continue");
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    private void emailConfirmationOnToggleMFA(UserModel user,
                                              UserModel.MfaType type,
                                              boolean toggle) {
        if (unleash.isEnabled(FeatureFlags.EMAIL_CONFIRMATION_ON_SELF_MFA_ENABLE_DISABLE.name())) {
            var action = toggle ? "enabled" : "disabled";
            mailService.sendEmailAsync(user.getEmail(), "MFA " + action + " confirmation", "Your " + type + " MFA has been " + action, MailService.MailType.SELF_MFA_ENABLE_DISABLE_CONFIRMATION);
        }
    }

    private void validateOTPTOTP(String otpTotp) {
        try {
            ValidationUtility.validateOTP(otpTotp, "OTP/TOTP");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid OTP/TOTP");
        }
    }

    private Map<String, String> verifyTOTPToEnableAuthenticatorApp(UserModel user,
                                                                   String totp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateOTPTOTP(totp);
        var encryptedSecretKey = getEncryptedSecretKey(user);
        var encryptedSecret = redisService.get(encryptedSecretKey);
        if (encryptedSecret != null) {
            var secret = authenticatorAppMFASecretRandomConverter.decrypt((String) encryptedSecret, String.class);
            if (TOTPUtility.verifyTOTP(secret, totp)) {
                try {
                    redisService.delete(encryptedSecretKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
                user.enableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
                user.setAuthAppSecret(authenticatorAppSecretRandomConverter.encrypt(secret));
                user.setUpdatedBy("SELF");
                jwtUtility.revokeTokens(user);
                userRepo.save(user);
                emailConfirmationOnToggleMFA(user, UserModel.MfaType.AUTHENTICATOR_APP, true);
                return Map.of("message", "Authenticator app MFA enabled successfully. Please log in again to continue");
            }
            throw new BadRequestException("Invalid TOTP");
        }
        throw new BadRequestException("Invalid TOTP");
    }

    private Map<String, String> verifyTOTPToDisableAuthenticatorAppMFA(UserModel user,
                                                                       String totp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        validateOTPTOTP(totp);
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp))
            throw new BadRequestException("Invalid TOTP");
        user.disableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
        user.setAuthAppSecret(null);
        user.setUpdatedBy("SELF");
        jwtUtility.revokeTokens(user);
        userRepo.save(user);
        emailConfirmationOnToggleMFA(user, UserModel.MfaType.AUTHENTICATOR_APP, false);
        return Map.of("message", "Authenticator app MFA disabled successfully. Please log in again to continue");
    }

    public Map<String, String> requestToLoginMFA(String type,
                                                 String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserUtility.validateTypeExistence(type);
        UserUtility.checkMFAEnabledGlobally(unleash);
        try {
            ValidationUtility.validateUuid(stateToken, "State token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid state token");
        }
        var user = getUser(stateToken);
        var mfaType = UserModel.MfaType.valueOf(type.toUpperCase());
        switch (mfaType) {
            case UserModel.MfaType.EMAIL -> {
                if (user.getEnabledMfaMethods().isEmpty()) {
                    if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                        mailService.sendEmailAsync(user.getEmail(), "OTP to verify email MFA to login", generateOTPForEmailMFA(user), MailService.MailType.OTP);
                        return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
                    }
                    throw new BadRequestException("Email MFA is not enabled");
                } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                    if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                        throw new ServiceUnavailableException("Email MFA is disabled globally");
                    mailService.sendEmailAsync(user.getEmail(), "OTP to verify email MFA to login", generateOTPForEmailMFA(user), MailService.MailType.OTP);
                    return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
                } else throw new BadRequestException("Email MFA is not enabled");
            }
            case UserModel.MfaType.AUTHENTICATOR_APP -> {
                if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
                    throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
                if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                    throw new BadRequestException("Authenticator app MFA is not enabled");
                return Map.of("message", "Please proceed to verify TOTP");
            }
            default ->
                    throw new BadRequestException("Unsupported MFA type: " + type + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private UserModel getUser(String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userRepo.findById(getUserIdFromEncryptedStateTokenMappingKey(getEncryptedStateTokenMappingKey(stateToken))).orElseThrow(() -> new BadRequestException("Invalid state token"));
    }

    private String getEncryptedStateTokenMappingKey(String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return stateTokenStaticConverter.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
    }

    private UUID getUserIdFromEncryptedStateTokenMappingKey(String encryptedStateTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedUserId = redisService.get(encryptedStateTokenMappingKey);
        if (encryptedUserId != null) return stateTokenRandomConverter.decrypt((String) encryptedUserId, UUID.class);
        throw new BadRequestException("Invalid state token");
    }

    public Map<String, Object> verifyMFAToLogin(String type,
                                                String stateToken,
                                                String otpTotp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        UserUtility.validateTypeExistence(type);
        UserUtility.checkMFAEnabledGlobally(unleash);
        try {
            ValidationUtility.validateUuid(stateToken, "State token");
            ValidationUtility.validateOTP(otpTotp, "OTP/TOTP");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid OTP/TOTP or state token");
        }
        var encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        var user = userRepo.findById(getUserIdFromEncryptedStateTokenMappingKey(encryptedStateTokenMappingKey)).orElseThrow(() -> new BadRequestException("Invalid state token"));
        var mfaType = UserModel.MfaType.valueOf(type.toUpperCase());
        switch (mfaType) {
            case UserModel.MfaType.EMAIL -> {
                if (user.getEnabledMfaMethods().isEmpty()) {
                    if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                        return verifyEmailOTPToLogin(user, otpTotp, encryptedStateTokenMappingKey);
                    }
                    throw new BadRequestException("Email MFA is not enabled");
                } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                    if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                        throw new ServiceUnavailableException("Email MFA is disabled globally");
                    return verifyEmailOTPToLogin(user, otpTotp, encryptedStateTokenMappingKey);
                } else throw new BadRequestException("Email MFA is not enabled");
            }
            case UserModel.MfaType.AUTHENTICATOR_APP -> {
                if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
                    throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
                if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                    throw new BadRequestException("Authenticator app MFA is not enabled");
                return verifyAuthenticatorAppTOTPToLogin(user, otpTotp, encryptedStateTokenMappingKey);
            }
            default ->
                    throw new BadRequestException("Unsupported MFA type: " + type + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private Map<String, Object> verifyEmailOTPToLogin(UserModel user,
                                                      String otp,
                                                      String encryptedStateTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        var encryptedEmailMFAOTPKey = getEncryptedEmailMFAOTPKey(user);
        var encryptedOTP = redisService.get(encryptedEmailMFAOTPKey);
        if (encryptedOTP != null) {
            if (emailOTPRandomConverter.decrypt((String) encryptedOTP, String.class).equals(otp)) {
                try {
                    redisService.deleteAll(Set.of(getEncryptedStateTokenKey(user), encryptedStateTokenMappingKey, encryptedEmailMFAOTPKey));
                } catch (Exception ignored) {
                }
                return jwtUtility.generateTokens(user);
            }
            handleFailedMFALoginAttempt(user);
            throw new BadRequestException("Invalid OTP");
        }
        handleFailedMFALoginAttempt(user);
        throw new BadRequestException("Invalid OTP");
    }

    private void handleFailedMFALoginAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        userRepo.save(user);
    }

    private Map<String, Object> verifyAuthenticatorAppTOTPToLogin(UserModel user,
                                                                  String totp,
                                                                  String encryptedStateTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        if (TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp)) {
            try {
                redisService.deleteAll(Set.of(getEncryptedStateTokenKey(user), encryptedStateTokenMappingKey));
            } catch (Exception ignored) {
            }
            return jwtUtility.generateTokens(user);
        }
        handleFailedMFALoginAttempt(user);
        throw new BadRequestException("Invalid TOTP");
    }
}
