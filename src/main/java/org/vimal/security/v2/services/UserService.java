package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.converter.*;
import org.vimal.security.v2.dtos.*;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final Set<String> REMOVE_DOTS = Set.of("gmail.com", "googlemail.com");
    private static final Set<String> REMOVE_ALIAS_PART = Set.of("gmail.com", "googlemail.com", "live.com", "protonmail.com", "hotmail.com", "outlook.com");
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "SECURITY_V2_FORGOT_PASSWORD_OTP:";
    private static final String EMAIL_CHANGE_OTP_PREFIX = "SECURITY_V2_EMAIL_CHANGE_OTP:";
    private static final String EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX = "SECURITY_V2_EMAIL_CHANGE_OTP_FOR_OLD_EMAIL:";
    private static final String EMAIL_STORE_PREFIX = "SECURITY_V2_EMAIL_STORE:";
    private static final String EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX = "SECURITY_V2_EMAIL_OTP_TO_DELETE_ACCOUNT:";
    private static final String EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX = "SECURITY_V2_EMAIL_OTP_FOR_PASSWORD_CHANGE:";
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final RedisService redisService;
    private final Unleash unleash;
    private final JWTUtility jwtUtility;
    private final EmailVerificationTokenStaticConverter emailVerificationTokenStaticConverter;
    private final EmailVerificationTokenRandomConverter emailVerificationTokenRandomConverter;
    private final EmailOTPForPWDResetStaticConverter emailOTPForPWDResetStaticConverter;
    private final EmailOTPForPWDResetRandomConverter emailOTPForPWDResetRandomConverter;
    private final EmailOTPForEmailChangeStaticConverter emailOTPForEmailChangeStaticConverter;
    private final EmailOTPForEmailChangeRandomConverter emailOTPForEmailChangeRandomConverter;
    private final EmailStoreStaticConverter emailStoreStaticConverter;
    private final EmailStoreRandomConverter emailStoreRandomConverter;
    private final EmailOTPForEmailChangeForOldEmailStaticConverter emailOTPForEmailChangeForOldEmailStaticConverter;
    private final EmailOTPForEmailChangeForOldEmailRandomConverter emailOTPForEmailChangeForOldEmailRandomConverter;
    private final EmailOTPToDeleteAccountStaticConverter emailOTPToDeleteAccountStaticConverter;
    private final EmailOTPToDeleteAccountRandomConverter emailOTPToDeleteAccountRandomConverter;
    private final AuthenticatorAppSecretRandomConverter authenticatorAppSecretRandomConverter;
    private final EmailOTPForPasswordChangeStaticConverter emailOTPForPasswordChangeStaticConverter;
    private final EmailOTPForPasswordChangeRandomConverter emailOTPForPasswordChangeRandomConverter;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.REGISTRATION_ENABLED.name())) {
            var invalidInputs = UserUtility.validateInputs(dto);
            if (!invalidInputs.isEmpty())
                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
            if (userRepo.existsByUsername(dto.getUsername()))
                throw new BadRequestException("Username: '" + dto.getUsername() + "' is already taken");
            if (userRepo.existsByEmail(dto.getEmail()))
                throw new BadRequestException("Email: '" + dto.getEmail() + "' is already registered");
            var sanitizedEmail = sanitizeEmail(dto.getEmail());
            if (userRepo.existsByRealEmail(sanitizedEmail))
                throw new BadRequestException("Alias version of email: '" + dto.getEmail() + "' is already registered");
            var user = toUserModel(dto, sanitizedEmail);
            var shouldVerifyRegisteredEmail = unleash.isEnabled(FeatureFlags.REGISTRATION_EMAIL_VERIFICATION.name());
            user.setEmailVerified(!shouldVerifyRegisteredEmail);
            if (shouldVerifyRegisteredEmail) {
                mailService.sendLinkEmailAsync(user.getEmail(), "Email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
                return ResponseEntity.ok(Map.of("message", "Registration successful. Please check your email for verification link", "user", userRepo.save(user)));
            }
            return ResponseEntity.ok(Map.of("message", "Registration successful", "user", userRepo.save(user)));
        }
        throw new ServiceUnavailableException("Registration is currently disabled. Please try again later");
    }

    private String sanitizeEmail(String email) {
        var lowerCasedEmail = email.trim().toLowerCase();
        var atIndex = lowerCasedEmail.indexOf('@');
        var local = lowerCasedEmail.substring(0, atIndex);
        var domain = lowerCasedEmail.substring(atIndex + 1);
        if (REMOVE_DOTS.contains(domain)) local = local.replace(".", "");
        if (REMOVE_ALIAS_PART.contains(domain)) {
            var plusIndex = local.indexOf('+');
            if (plusIndex != -1) local = local.substring(0, plusIndex);
        }
        return local + "@" + domain;
    }

    private UserModel toUserModel(RegistrationDto dto, String sanitizedEmail) {
        return UserModel.builder()
                .username(dto.getUsername())
                .password(passwordEncoder.encode(dto.getPassword()))
                .email(dto.getEmail())
                .realEmail(sanitizedEmail)
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .createdBy("SELF")
                .updatedBy("SELF")
                .build();
    }

    private UUID generateEmailVerificationToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedEmailVerificationTokenKey = getEncryptedEmailVerificationTokenKey(user);
        var existingEncryptedEmailVerificationToken = redisService.get(encryptedEmailVerificationTokenKey);
        if (existingEncryptedEmailVerificationToken != null)
            return emailVerificationTokenRandomConverter.decrypt((String) existingEncryptedEmailVerificationToken, UUID.class);
        var emailVerificationToken = UUID.randomUUID();
        var encryptedEmailVerificationTokenMappingKey = emailVerificationTokenStaticConverter.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
        try {
            redisService.save(encryptedEmailVerificationTokenKey, emailVerificationTokenRandomConverter.encrypt(emailVerificationToken), RedisService.DEFAULT_TTL);
            redisService.save(encryptedEmailVerificationTokenMappingKey, emailVerificationTokenRandomConverter.encrypt(user.getId()), RedisService.DEFAULT_TTL);
            return emailVerificationToken;
        } catch (Exception ex) {
            redisService.deleteAll(Set.of(encryptedEmailVerificationTokenKey, encryptedEmailVerificationTokenMappingKey));
            throw new RuntimeException("Failed to generate email verification token", ex);
        }
    }

    private String getEncryptedEmailVerificationTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailVerificationTokenStaticConverter.encrypt(EMAIL_VERIFICATION_TOKEN_PREFIX + user.getId());
    }

    public UserSummaryDto getSelfDetails() {
        var user = userRepo.findById(UserUtility.getCurrentAuthenticatedUser().getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        return MapperUtility.toUserSummaryDto(user);
    }

    public Map<String, Object> verifyEmail(String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateUuid(emailVerificationToken, "Email verification token");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid email verification token");
        }
        var encryptedEmailVerificationTokenMappingKey = getEncryptedEmailVerificationTokenMappingKey(emailVerificationToken);
        var user = userRepo.findById(getUserIdFromEncryptedEmailVerificationTokenMappingKey(encryptedEmailVerificationTokenMappingKey)).orElseThrow(() -> new BadRequestException("Invalid email verification token"));
        if (user.isEmailVerified()) throw new BadRequestException("Email is already verified");
        user.setEmailVerified(true);
        user.setUpdatedBy("SELF");
        try {
            redisService.deleteAll(Set.of(getEncryptedEmailVerificationTokenKey(user), encryptedEmailVerificationTokenMappingKey));
        } catch (Exception ignored) {
        }
        return Map.of("message", "Email verification successful", "user", MapperUtility.toUserSummaryDto(userRepo.save(user)));
    }

    private String getEncryptedEmailVerificationTokenMappingKey(String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailVerificationTokenStaticConverter.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
    }

    private UUID getUserIdFromEncryptedEmailVerificationTokenMappingKey(String encryptedEmailVerificationTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedUserId = redisService.get(encryptedEmailVerificationTokenMappingKey);
        if (encryptedUserId != null)
            return emailVerificationTokenRandomConverter.decrypt((String) encryptedUserId, UUID.class);
        throw new BadRequestException("Invalid email verification token");
    }

    public Map<String, String> resendEmailVerificationLink(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            return proceedResendEmailVerificationLink(getUserByUsernameOrEmail(usernameOrEmail));
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    private UserModel getUserByUsernameOrEmail(String usernameOrEmail) {
        try {
            ValidationUtility.validateStringNonNullAndNotEmpty(usernameOrEmail, "Username/email");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid username/email");
        }
        UserModel user;
        if (ValidationUtility.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            user = userRepo.findByUsername(usernameOrEmail).orElseThrow(() -> new BadRequestException("Invalid username"));
        else if (ValidationUtility.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            user = userRepo.findByEmail(usernameOrEmail).orElseThrow(() -> new BadRequestException("Invalid email"));
        else throw new BadRequestException("Invalid username/email");
        return user;
    }

    private Map<String, String> proceedResendEmailVerificationLink(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (user.isEmailVerified()) throw new BadRequestException("Email is already verified");
        mailService.sendLinkEmailAsync(user.getEmail(), "Resending email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
        return Map.of("message", "Email verification link resent successfully. Please check your email");
    }

    public ResponseEntity<Map<String, Object>> forgotPassword(String usernameOrEmail) {
        var user = getUserByUsernameOrEmail(usernameOrEmail);
        if (!user.isEmailVerified())
            return ResponseEntity.badRequest().body(Map.of("message", "Email is not verified. Please verify your email before resetting password"));
        var methods = user.getEnabledMfaMethods();
        methods.add(UserModel.MfaType.EMAIL);
        return ResponseEntity.ok(Map.of("message", "Please select a method to receive OTP for password reset", "methods", methods));
    }

    public Map<String, String> forgotPasswordMethodSelection(String usernameOrEmail,
                                                             String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserUtility.validateTypeExistence(method);
        var methodType = UserModel.MfaType.valueOf(method.toUpperCase());
        var user = getUserByUsernameOrEmail(usernameOrEmail);
        var methods = user.getEnabledMfaMethods();
        methods.add(UserModel.MfaType.EMAIL);
        if (!user.hasMfaEnabled(methodType))
            throw new BadRequestException("MFA method: '" + method + "' is not enabled for user");
        switch (methodType) {
            case UserModel.MfaType.EMAIL -> {
                mailService.sendOtpAsync(user.getEmail(), "OTP for resetting password", generateOTPForForgotPassword(user));
                return Map.of("Message", "OTP sent to your email. Please check your email to reset your password");
            }
            case UserModel.MfaType.AUTHENTICATOR_APP -> {
                return Map.of("message", "Please proceed to verify TOTP");
            }
            default ->
                    throw new BadRequestException("Unsupported MFA type: " + method + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private String generateOTPForForgotPassword(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = UUID.randomUUID().toString();
        redisService.save(getEncryptedForgotPasswordOtpKey(user), emailOTPForPWDResetRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedForgotPasswordOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForPWDResetStaticConverter.encrypt(FORGOT_PASSWORD_OTP_PREFIX + user.getId());
    }

    public ResponseEntity<Map<String, Object>> resetPassword(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserUtility.validateTypeExistence(dto.getMethod());
        var invalidInputs = validateInputs(dto);
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var methodType = UserModel.MfaType.valueOf(dto.getMethod().toUpperCase());
        var user = getUserByUsernameOrEmail(dto.getUsernameOrEmail());
        var methods = user.getEnabledMfaMethods();
        methods.add(UserModel.MfaType.EMAIL);
        if (!user.hasMfaEnabled(methodType))
            throw new BadRequestException("MFA method: '" + dto.getMethod() + "' is not enabled for user");
        switch (methodType) {
            case UserModel.MfaType.EMAIL -> {
                return ResponseEntity.ok(verifyEmailOTPForResetPassword(user, dto));
            }
            case UserModel.MfaType.AUTHENTICATOR_APP -> {
                if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                    throw new BadRequestException("Authenticator app is not enabled");
                return ResponseEntity.ok(verifyAuthenticatorAppTOTPToResetPassword(user, dto));
            }
            default ->
                    throw new BadRequestException("Unsupported MFA type: " + dto.getMethod() + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private Set<String> validateInputs(ResetPwdDto dto) {
        var validationErrors = validateInputsPasswordAndConfirmPassword(dto);
        try {
            ValidationUtility.validateStringNonNullAndNotEmpty(dto.getUsernameOrEmail(), "Username/email");
        } catch (BadRequestException ex) {
            validationErrors.add("Invalid username/email");
        }
        try {
            ValidationUtility.validateOTP(dto.getOtpTotp(), "OTP");
        } catch (BadRequestException ex) {
            validationErrors.add("Invalid OTP");
        }
        return validationErrors;
    }

    private Set<String> validateInputsPasswordAndConfirmPassword(ResetPwdDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationUtility.validatePassword(dto.getPassword());
            if (!dto.getPassword().equals(dto.getConfirmPassword()))
                validationErrors.add("New password: '" + dto.getPassword() + "' and confirm password: '" + dto.getConfirmPassword() + "' do not match");
        } catch (BadRequestException ex) {
            validationErrors.add("New " + ex.getMessage());
        }
        return validationErrors;
    }

    private Map<String, Object> verifyEmailOTPForResetPassword(UserModel user,
                                                               ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedForgotPasswordOtpKey = getEncryptedForgotPasswordOtpKey(user);
        var encryptedOtp = redisService.get(encryptedForgotPasswordOtpKey);
        if (encryptedOtp != null) {
            if (emailOTPForPWDResetRandomConverter.decrypt((String) encryptedOtp, String.class).equals(dto.getOtpTotp())) {
                try {
                    redisService.delete(encryptedForgotPasswordOtpKey);
                } catch (Exception ignored) {
                }
                selfChangePassword(user, dto.getPassword());
                return Map.of("message", "Password reset successful");
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    private void selfChangePassword(UserModel user,
                                    String password) {
        user.changePassword(passwordEncoder.encode(password));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
    }

    private Map<String, Object> verifyAuthenticatorAppTOTPToResetPassword(UserModel user,
                                                                          ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), dto.getOtpTotp()))
            throw new BadRequestException("Invalid TOTP");
        selfChangePassword(user, dto.getPassword());
        return Map.of("message", "Password reset successful");
    }

    public ResponseEntity<Map<String, Object>> changePassword(ChangePwdDto dto) {
        var invalidInputs = validateInputsPasswordAndConfirmPassword(dto);
        try {
            ValidationUtility.validatePassword(dto.getOldPassword());
        } catch (BadRequestException ex) {
            invalidInputs.add("Invalid old password");
        }
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (unleash.isEnabled(FeatureFlags.MFA.name())) {
            if (UserUtility.shouldDoMFA(user, unleash))
                return ResponseEntity.ok(Map.of("message", "Please select a method to receive OTP for password change", "methods", user.getEnabledMfaMethods()));
            if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                return ResponseEntity.ok(Map.of("message", "Please select a method to receive OTP for password change", "methods", Set.of(UserModel.MfaType.EMAIL)));
        }
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword()))
            throw new BadRequestException("Invalid old password");
        selfChangePassword(user, dto.getPassword());
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    public Map<String, String> changePasswordMethodSelection(String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserUtility.validateTypeExistence(method);
        UserUtility.checkMFAEnabledGlobally(unleash);
        var user = UserUtility.getCurrentAuthenticatedUser();
        var methodType = UserModel.MfaType.valueOf(method.toUpperCase());
        switch (methodType) {
            case UserModel.MfaType.EMAIL -> {
                if (user.getEnabledMfaMethods().isEmpty()) {
                    if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                        mailService.sendOtpAsync(user.getEmail(), "OTP for password change", generateOTPForPasswordChange(user));
                        return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
                    }
                    throw new BadRequestException("Email MFA is not enabled");
                } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                    if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                        throw new ServiceUnavailableException("Email MFA is disabled globally");
                    mailService.sendOtpAsync(user.getEmail(), "OTP for password change", generateOTPForPasswordChange(user));
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
                    throw new BadRequestException("Unsupported MFA type: " + method + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private String generateOTPForPasswordChange(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedPasswordChangeOTPKey(user), emailOTPForPasswordChangeRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedPasswordChangeOTPKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForPasswordChangeStaticConverter.encrypt(EMAIL_OTP_FOR_PASSWORD_CHANGE_PREFIX + user.getId());
    }

    public ResponseEntity<Map<String, Object>> verifyChangePassword(ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        UserUtility.validateTypeExistence(dto.getMethod());
        var invalidInputs = validateInputsPasswordAndConfirmPassword(dto);
        try {
            ValidationUtility.validateOTP(dto.getOtpTotp(), "OTP/TOTP");
        } catch (BadRequestException ex) {
            invalidInputs.add("Invalid OTP/TOTP");
        }
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        UserUtility.checkMFAEnabledGlobally(unleash);
        var user = UserUtility.getCurrentAuthenticatedUser();
        var methodType = UserModel.MfaType.valueOf(dto.getMethod().toUpperCase());
        switch (methodType) {
            case UserModel.MfaType.EMAIL -> {
                if (user.getEnabledMfaMethods().isEmpty()) {
                    if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                        return ResponseEntity.ok(verifyEmailOTPToChangePassword(user, dto));
                    }
                    throw new BadRequestException("Email MFA is not enabled");
                } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                    if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                        throw new ServiceUnavailableException("Email MFA is disabled globally");
                    return ResponseEntity.ok(verifyEmailOTPToChangePassword(user, dto));
                } else throw new BadRequestException("Email MFA is not enabled");
            }
            case UserModel.MfaType.AUTHENTICATOR_APP -> {
                if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
                    throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
                if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                    throw new BadRequestException("Authenticator app MFA is not enabled");
                return ResponseEntity.ok(verifyAuthenticatorAppTOTPToChangePassword(user, dto));
            }
            default ->
                    throw new BadRequestException("Unsupported MFA type: " + dto.getMethod() + ". Supported types: " + UserUtility.MFA_METHODS);
        }
    }

    private Map<String, Object> verifyEmailOTPToChangePassword(UserModel user,
                                                               ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedPasswordChangeOTPKey = getEncryptedPasswordChangeOTPKey(user);
        var encryptedOtp = redisService.get(encryptedPasswordChangeOTPKey);
        if (encryptedOtp != null) {
            if (emailOTPForPasswordChangeRandomConverter.decrypt((String) encryptedOtp, String.class).equals(dto.getOtpTotp())) {
                try {
                    redisService.delete(encryptedPasswordChangeOTPKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
                selfChangePassword(user, dto.getPassword());
                return Map.of("message", "Password change successful");
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    private Map<String, Object> verifyAuthenticatorAppTOTPToChangePassword(UserModel user,
                                                                           ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), dto.getOtpTotp()))
            throw new BadRequestException("Invalid TOTP");
        selfChangePassword(user, dto.getPassword());
        return Map.of("message", "Password change successful");
    }

    public Map<String, String> emailChangeRequest(String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.EMAIL_CHANGE_ENABLED.name())) {
            ValidationUtility.validateEmail(newEmail);
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (user.getEmail().equals(newEmail))
                throw new BadRequestException("New email cannot be same as current email");
            if (userRepo.existsByEmail(newEmail))
                throw new BadRequestException("Email: '" + newEmail + "' is already registered");
            var sanitizedEmail = sanitizeEmail(newEmail);
            if (!user.getRealEmail().equals(sanitizedEmail)) if (userRepo.existsByRealEmail(sanitizedEmail))
                throw new BadRequestException("Alias version of email: '" + newEmail + "' is already registered");
            storeNewEmailForEmailChange(user, newEmail);
            mailService.sendOtpAsync(newEmail, "OTP for email change", generateOTPForEmailChange(user));
            mailService.sendOtpAsync(user.getEmail(), "OTP for email change for old email", generateOTPForEmailChangeForOldEmail(user));
            return Map.of("message", "OTP sent to your new & old email. Please check your email to verify your email change");
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    private void storeNewEmailForEmailChange(UserModel user,
                                             String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        redisService.save(getEncryptedEmailKey(user), emailStoreRandomConverter.encrypt(newEmail), RedisService.DEFAULT_TTL);
    }

    private String getEncryptedEmailKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailStoreStaticConverter.encrypt(EMAIL_STORE_PREFIX + user.getId());
    }

    private String generateOTPForEmailChange(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedEmailChangeOTPKey(user), emailOTPForEmailChangeRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedEmailChangeOTPKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForEmailChangeStaticConverter.encrypt(EMAIL_CHANGE_OTP_PREFIX + user.getId());
    }

    private String generateOTPForEmailChangeForOldEmail(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedEmailChangeForOldEmailOTPKey(user), emailOTPForEmailChangeForOldEmailRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedEmailChangeForOldEmailOTPKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForEmailChangeForOldEmailStaticConverter.encrypt(EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX + user.getId());
    }

    public Map<String, Object> verifyEmailChange(String newEmailOtp,
                                                 String oldEmailOtp,
                                                 String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.EMAIL_CHANGE_ENABLED.name())) {
            try {
                ValidationUtility.validateOTP(newEmailOtp, "New email OTP");
                ValidationUtility.validateOTP(oldEmailOtp, "Old email OTP");
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid OTPs");
            }
            var user = UserUtility.getCurrentAuthenticatedUser();
            var encryptedEmailChangeOTPKey = getEncryptedEmailChangeOTPKey(user);
            var encryptedNewEmailOtp = redisService.get(encryptedEmailChangeOTPKey);
            if (Objects.isNull(encryptedNewEmailOtp)) throw new BadRequestException("Invalid OTPs");
            if (!emailOTPForEmailChangeRandomConverter.decrypt((String) encryptedNewEmailOtp, String.class).equals(newEmailOtp))
                throw new BadRequestException("Invalid OTPs");
            var encryptedEmailChangeForOldEmailOTPKey = getEncryptedEmailChangeForOldEmailOTPKey(user);
            var encryptedOldEmailOtp = redisService.get(encryptedEmailChangeForOldEmailOTPKey);
            if (Objects.isNull(encryptedOldEmailOtp)) throw new BadRequestException("Invalid OTPs");
            if (!emailOTPForEmailChangeForOldEmailRandomConverter.decrypt((String) encryptedOldEmailOtp, String.class).equals(oldEmailOtp))
                throw new BadRequestException("Invalid OTPs");
            var encryptedEmailKey = getEncryptedEmailKey(user);
            var encryptedNewEmail = redisService.get(encryptedEmailKey);
            if (Objects.isNull(encryptedNewEmail)) throw new BadRequestException("Invalid email change request");
            var newEmail = emailStoreRandomConverter.decrypt((String) encryptedNewEmail, String.class);
            if (user.getEmail().equals(newEmail))
                throw new BadRequestException("New email cannot be same as current email");
            if (userRepo.existsByEmail(newEmail))
                throw new BadRequestException("Email: '" + newEmail + "' is already registered");
            var sanitizedEmail = sanitizeEmail(newEmail);
            if (!user.getRealEmail().equals(sanitizedEmail)) if (userRepo.existsByRealEmail(sanitizedEmail))
                throw new BadRequestException("Alias version of email: '" + newEmail + "' is already registered");
            user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword()))
                throw new BadRequestException("Invalid password");
            user.setEmail(newEmail);
            user.setRealEmail(sanitizedEmail);
            jwtUtility.revokeTokens(user);
            try {
                redisService.deleteAll(Set.of(encryptedEmailChangeOTPKey, encryptedEmailChangeForOldEmailOTPKey, encryptedEmailKey));
            } catch (Exception ignored) {
            }
            return Map.of("message", "Email change successful. Please login again to continue", "user", MapperUtility.toUserSummaryDto(userRepo.save(user)));
        }
        throw new ServiceUnavailableException("Email change is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> deleteAccount(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            try {
                ValidationUtility.validatePassword(password);
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid password");
            }
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (unleash.isEnabled(FeatureFlags.MFA.name())) {
                if (UserUtility.shouldDoMFA(user, unleash))
                    return ResponseEntity.ok(Map.of("message", "Please select a method to receive OTP for account deletion", "methods", user.getEnabledMfaMethods()));
                if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                    return ResponseEntity.ok(Map.of("message", "Please select a method to receive OTP for account deletion", "methods", Set.of(UserModel.MfaType.EMAIL)));
            }
            user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword()))
                throw new BadRequestException("Invalid old password");
            selfDeleteAccount(user);
            return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private void selfDeleteAccount(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        jwtUtility.revokeTokens(user);
        user.recordAccountDeletion(true, "SELF");
        userRepo.save(user);
        if (unleash.isEnabled(FeatureFlags.EMAIL_CONFIRMATION_ON_SELF_ACCOUNT_DELETION.name()))
            mailService.sendAccountDeletionConfirmationAsync(user.getEmail(), "Account deletion confirmation");
    }

    public Map<String, String> deleteAccountMethodSelection(String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            UserUtility.validateTypeExistence(method);
            UserUtility.checkMFAEnabledGlobally(unleash);
            var user = UserUtility.getCurrentAuthenticatedUser();
            var methodType = UserModel.MfaType.valueOf(method.toUpperCase());
            switch (methodType) {
                case UserModel.MfaType.EMAIL -> {
                    if (user.getEnabledMfaMethods().isEmpty()) {
                        if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                            mailService.sendOtpAsync(user.getEmail(), "OTP for account deletion", generateOTPForAccountDeletion(user));
                            return Map.of("message", "OTP sent to your registered email address. Please check your email to continue");
                        }
                        throw new BadRequestException("Email MFA is not enabled");
                    } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                            throw new ServiceUnavailableException("Email MFA is disabled globally");
                        mailService.sendOtpAsync(user.getEmail(), "OTP for account deletion", generateOTPForAccountDeletion(user));
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
                        throw new BadRequestException("Unsupported MFA type: " + method + ". Supported types: " + UserUtility.MFA_METHODS);
            }
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private String generateOTPForAccountDeletion(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedEmailOTPToDeleteAccountKey(user), emailOTPToDeleteAccountRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedEmailOTPToDeleteAccountKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPToDeleteAccountStaticConverter.encrypt(EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX + user.getId());
    }

    public Map<String, String> verifyDeleteAccount(String otpTotp,
                                                   String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            UserUtility.validateTypeExistence(method);
            try {
                ValidationUtility.validateOTP(otpTotp, "OTP/TOTP");
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid OTP/TOTP");
            }
            UserUtility.checkMFAEnabledGlobally(unleash);
            var user = UserUtility.getCurrentAuthenticatedUser();
            var methodType = UserModel.MfaType.valueOf(method.toUpperCase());
            switch (methodType) {
                case UserModel.MfaType.EMAIL -> {
                    if (user.getEnabledMfaMethods().isEmpty()) {
                        if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name())) {
                            return verifyEmailOTPToDeleteAccount(otpTotp, user);
                        }
                        throw new BadRequestException("Email MFA is not enabled");
                    } else if (user.hasMfaEnabled(UserModel.MfaType.EMAIL)) {
                        if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                            throw new ServiceUnavailableException("Email MFA is disabled globally");
                        return verifyEmailOTPToDeleteAccount(otpTotp, user);
                    } else throw new BadRequestException("Email MFA is not enabled");
                }
                case UserModel.MfaType.AUTHENTICATOR_APP -> {
                    if (!unleash.isEnabled(FeatureFlags.MFA_AUTHENTICATOR_APP.name()))
                        throw new ServiceUnavailableException("Authenticator app MFA is disabled globally");
                    if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                        throw new BadRequestException("Authenticator app MFA is not enabled");
                    return verifyAuthenticatorAppTOTPToDeleteAccount(otpTotp, user);
                }
                default ->
                        throw new BadRequestException("Unsupported MFA type: " + method + ". Supported types: " + UserUtility.MFA_METHODS);
            }
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    private Map<String, String> verifyEmailOTPToDeleteAccount(String otp,
                                                              UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedEmailOTPToDeleteAccountKey = getEncryptedEmailOTPToDeleteAccountKey(user);
        var encryptedOtp = redisService.get(encryptedEmailOTPToDeleteAccountKey);
        if (encryptedOtp != null) {
            if (emailOTPToDeleteAccountRandomConverter.decrypt((String) encryptedOtp, String.class).equals(otp)) {
                try {
                    redisService.delete(encryptedEmailOTPToDeleteAccountKey);
                } catch (Exception ignored) {
                }
                user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
                selfDeleteAccount(user);
                return Map.of("message", "Account deleted successfully");
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    private Map<String, String> verifyAuthenticatorAppTOTPToDeleteAccount(String totp,
                                                                          UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp))
            throw new BadRequestException("Invalid TOTP");
        selfDeleteAccount(user);
        return Map.of("message", "Account deleted successfully");
    }

    public ResponseEntity<Map<String, Object>> updateDetails(UpdationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = userRepo.findById(UserUtility.getCurrentAuthenticatedUser().getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        var userModificationResult = validateAndSet(user, dto);
        if (!userModificationResult.getInvalidInputs().isEmpty())
            return ResponseEntity.badRequest().body(Map.of("invalid_inputs", userModificationResult.getInvalidInputs()));
        if (userModificationResult.isModified()) {
            user.setUpdatedBy("SELF");
            if (userModificationResult.isShouldRemoveTokens()) {
                jwtUtility.revokeTokens(user);
                return ResponseEntity.ok(Map.of("message", "User details updated successfully. Please login again to continue", "user", MapperUtility.toUserSummaryDto(userRepo.save(user))));
            }
            return ResponseEntity.ok(Map.of("message", "User details updated successfully", "user", MapperUtility.toUserSummaryDto(userRepo.save(user))));
        }
        return ResponseEntity.ok(Map.of("message", "No details were updated", "user", MapperUtility.toUserSummaryDto(user)));
    }

    private UserDetailsResultDto validateAndSet(UserModel user,
                                                UpdationDto dto) {
        var userModificationResult = new UserDetailsResultDto(false, false, new HashSet<>());
        try {
            ValidationUtility.validatePassword(dto.getOldPassword());
            if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword()))
                userModificationResult.getInvalidInputs().add("Invalid old password");
        } catch (BadRequestException ex) {
            userModificationResult.getInvalidInputs().add("Invalid old password");
        }
        if (dto.getFirstName() != null && !dto.getFirstName().isBlank() && !dto.getFirstName().equals(user.getFirstName())) {
            try {
                ValidationUtility.validateFirstName(dto.getFirstName());
                user.setFirstName(dto.getFirstName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getMiddleName() != null && !dto.getMiddleName().isBlank() && !dto.getMiddleName().equals(user.getMiddleName())) {
            try {
                ValidationUtility.validateMiddleName(dto.getMiddleName());
                user.setMiddleName(dto.getMiddleName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getLastName() != null && !dto.getLastName().isBlank() && !dto.getLastName().equals(user.getLastName())) {
            try {
                ValidationUtility.validateLastName(dto.getLastName());
                user.setLastName(dto.getLastName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getUsername() != null && !dto.getUsername().isBlank() && !dto.getUsername().equals(user.getUsername())) {
            try {
                ValidationUtility.validateUsername(dto.getUsername());
                if (userRepo.existsByUsername(dto.getUsername())) {
                    userModificationResult.getInvalidInputs().add("Username already taken");
                } else {
                    user.setUsername(dto.getUsername());
                    userModificationResult.setModified(true);
                    userModificationResult.setShouldRemoveTokens(true);
                }
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        return userModificationResult;
    }
}
