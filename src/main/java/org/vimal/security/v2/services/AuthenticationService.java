package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.converter.*;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.impls.UserDetailsImpl;
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
    private final PasswordEncoder passwordEncoder;

    public Map<String, Object> loginUsername(String username,
                                             String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateUsername(username);
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        try {
            var authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            return handleSuccessfulLogin(authentication);
        } catch (BadCredentialsException ex) {
            if (ex.getCause() instanceof UsernameNotFoundException) throw ex;
            handleFailedLogin(username);
            throw ex;
        }
    }

    public Map<String, Object> handleSuccessfulLogin(Authentication authentication) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = ((UserDetailsImpl) authentication.getPrincipal()).getUserModel();
        if (unleash.isEnabled(FeatureFlags.MFA.name())) {
            if (user.isMfaEnabled() && !user.getEnabledMfaMethods().isEmpty()) {
                var shouldDoMFA = false;
                var unleashEmailMFA = unleash.isEnabled(FeatureFlags.MFA_EMAIL.name());
                var unleashAuthenticatorAppMFA = unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name());
                if (unleashEmailMFA && user.hasMfaEnabled(UserModel.MfaType.EMAIL)) shouldDoMFA = true;
                else if (unleashAuthenticatorAppMFA && user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                    shouldDoMFA = true;
                if (shouldDoMFA)
                    return Map.of("message", "MFA required", "state_token", generateStateToken(user), "mfa_methods", user.getEnabledMfaMethods());
            }
            if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                return Map.of("message", "MFA required. Please continue with email MFA", "state_token", generateStateToken(user));
        }
        return jwtUtility.generateTokens(user);
    }

    public UUID generateStateToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedStateTokenKey = stateTokenStaticConverter.encrypt(STATE_TOKEN_PREFIX + user.getId());
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
            redisService.delete(encryptedStateTokenKey);
            redisService.delete(encryptedStateTokenMappingKey);
            throw new RuntimeException("Failed to generate state token", ex);
        }
    }

    public void handleFailedLogin(String username) {
        var user = userRepo.findByUsername(username).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        user.recordFailedLoginAttempt();
        userRepo.save(user);
    }

    public void handleFailedLogin(UserModel user) {
        user.recordFailedLoginAttempt();
        userRepo.save(user);
    }

    public Map<String, Object> loginEmail(String email,
                                          String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateEmail(email);
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        var user = userRepo.findByEmail(email).orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
        try {
            var authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), password));
            return handleSuccessfulLogin(authentication);
        } catch (BadCredentialsException ex) {
            if (ex.getCause() instanceof UsernameNotFoundException) throw ex;
            handleFailedLogin(user);
            throw ex;
        }
    }

    public Map<String, Object> login(String usernameOrEmail,
                                     String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateStringNonNullAndNotEmpty(usernameOrEmail, "Username/email");
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadCredentialsException("Invalid credentials");
        }
        if (ValidationUtility.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return loginEmail(usernameOrEmail, password);
        else if (ValidationUtility.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return loginUsername(usernameOrEmail, password);
        else throw new BadCredentialsException("Invalid credentials");
    }

    public Map<String, String> logout() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUser();
        jwtUtility.revokeAccessToken(user);
        jwtUtility.revokeRefreshToken(user);
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

    public Map<String, String> sendEmailOTPToEnableEmailMFA() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestException("Email MFA is already enabled");
        mailService.sendOtpAsync(user.getEmail(), "OTP to enable email MFA", generateOTPForEmailMFA(user));
        return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
    }

    public String generateOTPForEmailMFA(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(emailOTPStaticConverter.encrypt(EMAIL_MFA_OTP_PREFIX + user.getId()), emailOTPRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    public Map<String, String> verifyEmailOTPToEnableEmailMFA(String otp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(otp, "OTP");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid OTP");
        }
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) throw new BadRequestException("Email MFA is already enabled");
        verifyOTPToToggleEmailMfa(user, otp);
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        user.enableMfaMethod(UserModel.MfaType.EMAIL);
        user.setUpdatedBy("SELF");
        jwtUtility.revokeAccessToken(user);
        jwtUtility.revokeRefreshToken(user);
        userRepo.save(user);
        return Map.of("message", "Email MFA enabled successfully. Please log in again to continue");
    }

    public void verifyOTPToToggleEmailMfa(UserModel user,
                                          String otp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedEmailOTPToEnableEmailMFAKey = emailOTPStaticConverter.encrypt(EMAIL_MFA_OTP_PREFIX + user.getId());
        var encryptedOTP = redisService.get(encryptedEmailOTPToEnableEmailMFAKey);
        if (encryptedOTP != null) {
            if (emailOTPRandomConverter.decrypt((String) encryptedOTP, String.class).equals(otp)) {
                redisService.delete(encryptedEmailOTPToEnableEmailMFAKey);
                return;
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    public Map<String, String> sendEmailOTPToVerifyEmailMFAToLogin(String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        var forcedMFA = unleash.isEnabled(FeatureFlags.FORCE_MFA.name());
        if (!forcedMFA) if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        try {
            ValidationUtility.validateUuid(stateToken, "State token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid state token");
        }
        var user = getUser(stateToken);
        if (!forcedMFA && !user.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestException("Email MFA is not enabled");
        mailService.sendOtpAsync(user.getEmail(), "OTP to verify email MFA to login", generateOTPForEmailMFA(user));
        return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
    }

    public UserModel getUser(String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userRepo.findById(getUserIdFromEncryptedStateTokenMappingKey(getEncryptedStateTokenMappingKey(stateToken))).orElseThrow(() -> new BadRequestException("Invalid state token"));
    }

    public String getEncryptedStateTokenMappingKey(String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return stateTokenStaticConverter.encrypt(STATE_TOKEN_MAPPING_PREFIX + stateToken);
    }

    public UUID getUserIdFromEncryptedStateTokenMappingKey(String encryptedStateTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedUserId = redisService.get(encryptedStateTokenMappingKey);
        if (encryptedUserId != null) return stateTokenRandomConverter.decrypt((String) encryptedUserId, UUID.class);
        throw new BadRequestException("Invalid state token");
    }

    public Map<String, Object> verifyEmailOTPToLogin(String otp,
                                                     String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        var forcedMFA = unleash.isEnabled(FeatureFlags.FORCE_MFA.name());
        if (!forcedMFA) if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(otp, "OTP");
            ValidationUtility.validateUuid(stateToken, "State token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid OTP or state token");
        }
        var encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        var user = userRepo.findById(getUserIdFromEncryptedStateTokenMappingKey(encryptedStateTokenMappingKey)).orElseThrow(() -> new BadRequestException("Invalid state token"));
        if (!forcedMFA && !user.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestException("Email MFA is not enabled");
        verifyOTPToLogin(user, otp);
        try {
            redisService.delete(Set.of(stateTokenStaticConverter.encrypt(STATE_TOKEN_PREFIX + user.getId()), encryptedStateTokenMappingKey));
        } catch (Exception ignored) {
        }
        return jwtUtility.generateTokens(user);
    }

    public void verifyOTPToLogin(UserModel user,
                                 String otp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        var encryptedEmailMFAOTPKey = emailOTPStaticConverter.encrypt(EMAIL_MFA_OTP_PREFIX + user.getId());
        var encryptedOTP = redisService.get(encryptedEmailMFAOTPKey);
        if (encryptedOTP != null) {
            if (emailOTPRandomConverter.decrypt((String) encryptedOTP, String.class).equals(otp)) {
                redisService.delete(encryptedEmailMFAOTPKey);
                return;
            }
            handleFailedMFALoginAttempt(user);
            throw new BadRequestException("Invalid OTP");
        }
        handleFailedMFALoginAttempt(user);
        throw new BadRequestException("Invalid OTP");
    }

    public void handleFailedMFALoginAttempt(UserModel user) {
        user.recordFailedMfaAttempt();
        userRepo.save(user);
    }

    public Map<String, String> sendEmailOTPToDisableEmailMFA() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestException("Email MFA is already disabled");
        mailService.sendOtpAsync(user.getEmail(), "OTP to disable email MFA", generateOTPForEmailMFA(user));
        return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
    }

    public Map<String, String> verifyEmailOTPToDisableEmailMFA(String otp,
                                                               String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
            throw new BadRequestException("Email MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(otp, "OTP");
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid OTP or password");
        }
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.EMAIL))
            throw new BadRequestException("Email MFA is already disabled");
        verifyOTPToToggleEmailMfa(user, otp);
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestException("Invalid password");
        user.disableMfaMethod(UserModel.MfaType.EMAIL);
        user.setUpdatedBy("SELF");
        jwtUtility.revokeAccessToken(user);
        jwtUtility.revokeRefreshToken(user);
        userRepo.save(user);
        return Map.of("message", "Email MFA disabled successfully. Please log in again to continue");
    }

    public byte[] generateQRCodeForAuthenticatorApp() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, IOException, WriterException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new BadRequestException("Authenticator app MFA is disabled globally");
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestException("Authenticator app MFA is already enabled");
        return QRUtility.generateQRCode(TOTPUtility.generateTOTPUrl("God Level Security", user.getUsername(), generateAuthenticatorAppSecret(user)));
    }

    public String generateAuthenticatorAppSecret(UserModel user) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var secret = TOTPUtility.generateBase32Secret();
        redisService.save(authenticatorAppMFASecretStaticConverter.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + user.getId()), authenticatorAppMFASecretRandomConverter.encrypt(secret), RedisService.DEFAULT_TTL);
        return secret;
    }

    public Map<String, String> verifyTOTPToSetupAuthenticatorApp(String totp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new BadRequestException("Authenticator app MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(totp, "TOTP");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid TOTP");
        }
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestException("Authenticator app MFA is already enabled");
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        verifyTOTP(user, totp);
        jwtUtility.revokeAccessToken(user);
        jwtUtility.revokeRefreshToken(user);
        userRepo.save(user);
        return Map.of("message", "Authenticator app MFA enabled successfully. Please log in again to continue");
    }

    public void verifyTOTP(UserModel user,
                           String totp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedSecretKey = authenticatorAppMFASecretStaticConverter.encrypt(AUTHENTICATOR_APP_SECRET_PREFIX + user.getId());
        var encryptedSecret = redisService.get(encryptedSecretKey);
        if (encryptedSecret != null) {
            var secret = authenticatorAppMFASecretRandomConverter.decrypt((String) encryptedSecret, String.class);
            if (TOTPUtility.verifyTOTP(secret, totp)) {
                user.enableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
                user.setAuthAppSecret(authenticatorAppSecretRandomConverter.encrypt(secret));
                user.setUpdatedBy("SELF");
                try {
                    redisService.delete(encryptedSecretKey);
                } catch (Exception ignored) {
                }
                return;
            }
            throw new BadRequestException("Invalid TOTP");
        }
        throw new BadRequestException("Invalid TOTP");
    }

    public Map<String, Object> verifyTOTPToLogin(String totp,
                                                 String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException, JoseException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new BadRequestException("Authenticator app MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(totp, "TOTP");
            ValidationUtility.validateUuid(stateToken, "State token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid TOTP or state token");
        }
        var encryptedStateTokenMappingKey = getEncryptedStateTokenMappingKey(stateToken);
        var user = userRepo.findById(getUserIdFromEncryptedStateTokenMappingKey(encryptedStateTokenMappingKey)).orElseThrow(() -> new BadRequestException("Invalid state token"));
        if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestException("Authenticator app MFA is not enabled");
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now()))
            throw new LockedException("Account is locked due to too many failed mfa attempts. Please try again later");
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp)) {
            handleFailedMFALoginAttempt(user);
            throw new BadRequestException("Invalid TOTP");
        }
        try {
            redisService.delete(Set.of(stateTokenStaticConverter.encrypt(STATE_TOKEN_PREFIX + user.getId()), encryptedStateTokenMappingKey));
        } catch (Exception ignored) {
        }
        return jwtUtility.generateTokens(user);
    }

    public Map<String, String> verifyTOTPToDisableAuthenticatorAppMFA(String totp,
                                                                      String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!unleash.isEnabled(FeatureFlags.MFA.name())) throw new BadRequestException("MFA is disabled globally");
        if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
            throw new BadRequestException("Authenticator app MFA is disabled globally");
        try {
            ValidationUtility.validateOTP(totp, "TOTP");
            ValidationUtility.validatePassword(password);
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid TOTP or password");
        }
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
            throw new BadRequestException("Authenticator app MFA is already disabled");
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp))
            throw new BadRequestException("Invalid TOTP");
        if (!passwordEncoder.matches(password, user.getPassword())) throw new BadRequestException("Invalid password");
        user.disableMfaMethod(UserModel.MfaType.AUTHENTICATOR_APP);
        user.setAuthAppSecret(null);
        user.setUpdatedBy("SELF");
        jwtUtility.revokeAccessToken(user);
        jwtUtility.revokeRefreshToken(user);
        userRepo.save(user);
        return Map.of("message", "Authenticator app MFA disabled successfully. Please log in again to continue");
    }
}
