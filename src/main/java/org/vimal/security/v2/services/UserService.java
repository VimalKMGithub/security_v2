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
    private static final Collection<String> REMOVE_DOTS = Set.of("gmail.com", "googlemail.com");
    private static final Collection<String> REMOVE_ALIAS_PART = Set.of("gmail.com", "googlemail.com", "live.com", "protonmail.com", "hotmail.com", "outlook.com");
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "SECURITY_V2_FORGOT_PASSWORD_OTP:";
    private static final String EMAIL_CHANGE_OTP_PREFIX = "SECURITY_V2_EMAIL_CHANGE_OTP:";
    private static final String EMAIL_CHANGE_OTP_FOR_OLD_EMAIL_PREFIX = "SECURITY_V2_EMAIL_CHANGE_OTP_FOR_OLD_EMAIL:";
    private static final String EMAIL_STORE_PREFIX = "SECURITY_V2_EMAIL_STORE:";
    private static final String EMAIL_OTP_TO_DELETE_ACCOUNT_PREFIX = "SECURITY_V2_EMAIL_OTP_TO_DELETE_ACCOUNT:";
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

    public Map<String, String> resendEmailVerificationLinkUsername(String username) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            try {
                ValidationUtility.validateUsername(username);
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid username");
            }
            var user = userRepo.findByUsername(username).orElseThrow(() -> new BadRequestException("Invalid username"));
            if (user.isEmailVerified()) throw new BadRequestException("Email is already verified");
            mailService.sendLinkEmailAsync(user.getEmail(), "Resending email verification link after registration using username", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
            return Map.of("message", "Email verification link resent successfully. Please check your email");
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    public Map<String, String> resendEmailVerificationLinkEmail(String email) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            try {
                ValidationUtility.validateEmail(email);
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid email");
            }
            var user = userRepo.findByEmail(email).orElseThrow(() -> new BadRequestException("Invalid email"));
            if (user.isEmailVerified()) throw new BadRequestException("Email is already verified");
            mailService.sendLinkEmailAsync(user.getEmail(), "Resending email verification link after registration using email", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
            return Map.of("message", "Email verification link resent successfully. Please check your email");
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    public Map<String, String> resendEmailVerificationLink(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.RESEND_REGISTRATION_EMAIL_VERIFICATION.name())) {
            try {
                ValidationUtility.validateStringNonNullAndNotEmpty(usernameOrEmail, "Username/email");
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid username/email");
            }
            if (ValidationUtility.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
                return resendEmailVerificationLinkUsername(usernameOrEmail);
            else if (ValidationUtility.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
                return resendEmailVerificationLinkEmail(usernameOrEmail);
            else throw new BadRequestException("Invalid username/email");
        }
        throw new ServiceUnavailableException("Resending email verification link is currently disabled. Please try again later");
    }

    public Map<String, String> forgotPasswordUsername(String username) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateUsername(username);
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid username");
        }
        var user = userRepo.findByUsername(username).orElseThrow(() -> new BadRequestException("Invalid username"));
        if (!user.isEmailVerified())
            throw new BadRequestException("Email is not verified. Please verify your email before resetting password");
        mailService.sendOtpAsync(user.getEmail(), "OTP for resetting password using username", generateOTPForForgotPassword(user));
        return Map.of("message", "OTP sent to your email. Please check your email to reset your password");
    }

    private String generateOTPForForgotPassword(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = UUID.randomUUID().toString();
        redisService.save(getEncryptedForgotPasswordOtpKey(user), emailOTPForPWDResetRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    private String getEncryptedForgotPasswordOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForPWDResetStaticConverter.encrypt(FORGOT_PASSWORD_OTP_PREFIX + user.getId());
    }

    public Map<String, String> forgotPasswordEmail(String email) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateEmail(email);
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid email");
        }
        var user = userRepo.findByEmail(email).orElseThrow(() -> new BadRequestException("Invalid email"));
        if (!user.isEmailVerified())
            throw new BadRequestException("Email is not verified. Please verify your email before resetting password");
        mailService.sendOtpAsync(user.getEmail(), "OTP for resetting password using email", generateOTPForForgotPassword(user));
        return Map.of("message", "OTP sent to your email. Please check your email to reset your password");
    }

    public Map<String, String> forgotPassword(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        try {
            ValidationUtility.validateStringNonNullAndNotEmpty(usernameOrEmail, "Username/email");
        } catch (BadRequestException ex) {
            throw new BadRequestException("Invalid username/email");
        }
        if (ValidationUtility.USERNAME_PATTERN.matcher(usernameOrEmail).matches())
            return forgotPasswordUsername(usernameOrEmail);
        else if (ValidationUtility.EMAIL_PATTERN.matcher(usernameOrEmail).matches())
            return forgotPasswordEmail(usernameOrEmail);
        else throw new BadRequestException("Invalid username/email");
    }

    public ResponseEntity<Map<String, Object>> resetPasswordUsername(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var invalidInputs = validateInputs(dto, "username");
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userRepo.findByUsername(dto.getUsername()).orElseThrow(() -> new BadRequestException("Invalid username"));
        verifyOTPForResetPassword(dto, user);
        user.changePassword(passwordEncoder.encode(dto.getPassword()));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    private Collection<String> validateInputs(ResetPwdDto dto,
                                              String type) {
        var validationErrors = validateInputsPasswordAndConfirmPassword(dto);
        switch (type) {
            case "username" -> {
                try {
                    ValidationUtility.validateUsername(dto.getUsername());
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid username");
                }
            }
            case "email" -> {
                try {
                    ValidationUtility.validateEmail(dto.getEmail());
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid email");
                }
            }
            case "usernameOrEmail" -> {
                try {
                    ValidationUtility.validateStringNonNullAndNotEmpty(dto.getUsernameOrEmail(), "Username/email");
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid username/email");
                }
            }
        }
        try {
            ValidationUtility.validateOTP(dto.getOtp(), "OTP");
        } catch (BadRequestException ex) {
            validationErrors.add("Invalid OTP");
        }
        return validationErrors;
    }

    private Collection<String> validateInputsPasswordAndConfirmPassword(ResetPwdDto dto) {
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

    private void verifyOTPForResetPassword(ResetPwdDto dto, UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var encryptedForgotPasswordOtpKey = getEncryptedForgotPasswordOtpKey(user);
        var encryptedOtp = redisService.get(encryptedForgotPasswordOtpKey);
        if (encryptedOtp != null) {
            if (emailOTPForPWDResetRandomConverter.decrypt((String) encryptedOtp, String.class).equals(dto.getOtp())) {
                redisService.delete(encryptedForgotPasswordOtpKey);
                return;
            }
            throw new BadRequestException("Invalid OTP");
        }
        throw new BadRequestException("Invalid OTP");
    }

    public ResponseEntity<Map<String, Object>> resetPasswordEmail(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var invalidInputs = validateInputs(dto, "email");
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userRepo.findByEmail(dto.getEmail()).orElseThrow(() -> new BadRequestException("Invalid email"));
        verifyOTPForResetPassword(dto, user);
        user.changePassword(passwordEncoder.encode(dto.getPassword()));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    public ResponseEntity<Map<String, Object>> resetPassword(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var invalidInputs = validateInputs(dto, "usernameOrEmail");
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        if (ValidationUtility.USERNAME_PATTERN.matcher(dto.getUsernameOrEmail()).matches()) {
            dto.setUsername(dto.getUsernameOrEmail());
            return resetPasswordUsername(dto);
        } else if (ValidationUtility.EMAIL_PATTERN.matcher(dto.getUsernameOrEmail()).matches()) {
            dto.setEmail(dto.getUsernameOrEmail());
            return resetPasswordEmail(dto);
        } else throw new BadRequestException("Invalid username/email");
    }

    public ResponseEntity<Map<String, Object>> resetPasswordUsingOldPassword(ResetPwdUsingOldPwdDto dto) {
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
                return ResponseEntity.badRequest().body(Map.of("message", "Since MFA is enabled in your account you cannot change password using old password only", "mfa_methods", user.getEnabledMfaMethods()));
            if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                return ResponseEntity.badRequest().body(Map.of("message", "Since MFA is forced globally you cannot change password using old password only", "mfa_methods", Set.of(UserModel.MfaType.EMAIL)));
        }
        user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword()))
            throw new BadRequestException("Invalid old password");
        user.changePassword(passwordEncoder.encode(dto.getPassword()));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
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

    public ResponseEntity<Map<String, Object>> deleteAccountPassword(String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            try {
                ValidationUtility.validatePassword(password);
            } catch (BadRequestException ex) {
                throw new BadRequestException("Invalid password");
            }
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (unleash.isEnabled(FeatureFlags.MFA.name())) {
                if (UserUtility.shouldDoMFA(user, unleash))
                    return ResponseEntity.badRequest().body(Map.of("message", "Since MFA is enabled in your account you cannot change delete your account using old password only", "mfa_methods", user.getEnabledMfaMethods()));
                if (unleash.isEnabled(FeatureFlags.FORCE_MFA.name()))
                    return ResponseEntity.badRequest().body(Map.of("message", "Since MFA is forced globally you cannot change delete your account using old password only", "mfa_methods", Set.of(UserModel.MfaType.EMAIL)));
            }
            user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword()))
                throw new BadRequestException("Invalid password");
            jwtUtility.revokeTokens(user);
            user.recordAccountDeletion(true, "SELF");
            userRepo.save(user);
            mailService.sendAccountDeletionConfirmationAsync(user.getEmail(), "Account deletion confirmation");
            return ResponseEntity.ok(Map.of("message", "Account deleted successfully"));
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    public Map<String, String> sendOTPToDeleteAccount() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            if (!unleash.isEnabled(FeatureFlags.MFA.name()))
                throw new ServiceUnavailableException("MFA is disabled globally");
            var forcedMFA = unleash.isEnabled(FeatureFlags.FORCE_MFA.name());
            if (!forcedMFA) if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                throw new ServiceUnavailableException("Email MFA is disabled globally");
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (!forcedMFA && !user.hasMfaEnabled(UserModel.MfaType.EMAIL))
                throw new BadRequestException("Email MFA is not enabled");
            mailService.sendOtpAsync(user.getEmail(), "OTP for account deletion", generateOTPForAccountDeletion(user));
            return Map.of("message", "OTP sent to your email. Please check your email to delete your account");
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

    public Map<String, String> verifyOTPToDeleteAccount(String otp,
                                                        String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            if (!unleash.isEnabled(FeatureFlags.MFA.name()))
                throw new ServiceUnavailableException("MFA is disabled globally");
            var forcedMFA = unleash.isEnabled(FeatureFlags.FORCE_MFA.name());
            if (!forcedMFA) if (!unleash.isEnabled(FeatureFlags.MFA_EMAIL.name()))
                throw new ServiceUnavailableException("Email MFA is disabled globally");
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (!forcedMFA && !user.hasMfaEnabled(UserModel.MfaType.EMAIL))
                throw new BadRequestException("Email MFA is not enabled");
            var encryptedEmailOTPToDeleteAccountKey = getEncryptedEmailOTPToDeleteAccountKey(user);
            var encryptedOtp = redisService.get(encryptedEmailOTPToDeleteAccountKey);
            if (Objects.isNull(encryptedOtp)) throw new BadRequestException("Invalid OTP");
            if (!emailOTPToDeleteAccountRandomConverter.decrypt((String) encryptedOtp, String.class).equals(otp))
                throw new BadRequestException("Invalid OTP");
            user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
            if (!passwordEncoder.matches(password, user.getPassword()))
                throw new BadRequestException("Invalid password");
            jwtUtility.revokeTokens(user);
            user.recordAccountDeletion(true, "SELF");
            userRepo.save(user);
            redisService.delete(encryptedEmailOTPToDeleteAccountKey);
            mailService.sendAccountDeletionConfirmationAsync(user.getEmail(), "Account deletion confirmation");
            return Map.of("message", "Account deleted successfully");
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
    }

    public Map<String, String> verifyTOTPToDeleteAccount(String totp,
                                                         String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.ACCOUNT_DELETION_ALLOWED.name())) {
            UserUtility.checkMFAAndAuthenticatorAppMFAEnabledGlobally(unleash);
            var user = UserUtility.getCurrentAuthenticatedUser();
            if (!user.hasMfaEnabled(UserModel.MfaType.AUTHENTICATOR_APP))
                throw new BadRequestException("Authenticator app MFA is disabled");
            user = userRepo.findById(user.getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
            if (!TOTPUtility.verifyTOTP(authenticatorAppSecretRandomConverter.decrypt(user.getAuthAppSecret(), String.class), totp))
                throw new BadRequestException("Invalid TOTP");
            if (!passwordEncoder.matches(password, user.getPassword()))
                throw new BadRequestException("Invalid password");
            jwtUtility.revokeTokens(user);
            user.recordAccountDeletion(true, "SELF");
            userRepo.save(user);
            mailService.sendAccountDeletionConfirmationAsync(user.getEmail(), "Account deletion confirmation");
            return Map.of("message", "Account deleted successfully");
        }
        throw new ServiceUnavailableException("Account deletion is currently disabled. Please try again later");
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
