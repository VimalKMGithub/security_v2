package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.converter.*;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.dtos.ResetPwdDto;
import org.vimal.security.v2.dtos.ResetPwdUsingOldPwdDto;
import org.vimal.security.v2.dtos.UserSummaryDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private static final String FORGOT_PASSWORD_OTP_PREFIX = "SECURITY_V2_FORGOT_PASSWORD_OTP:";
    private static final String EMAIL_CHANGE_OTP_PREFIX = "SECURITY_V2_EMAIL_CHANGE_OTP:";
    private static final String EMAIL_STORE_PREFIX = "SECURITY_V2_EMAIL_STORE:";
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final RedisService redisService;
    private final Unleash unleash;
    private final EmailVerificationTokenStaticConverter emailVerificationTokenStaticConverter;
    private final EmailVerificationTokenRandomConverter emailVerificationTokenRandomConverter;
    private final EmailOTPForPWDResetStaticConverter emailOTPForPWDResetStaticConverter;
    private final EmailOTPForPWDResetRandomConverter emailOTPForPWDResetRandomConverter;
    private final EmailOTPForEmailChangeStaticConverter emailOTPForEmailChangeStaticConverter;
    private final EmailOTPForEmailChangeRandomConverter emailOTPForEmailChangeRandomConverter;
    private final EmailStoreStaticConverter emailStoreStaticConverter;
    private final EmailStoreRandomConverter emailStoreRandomConverter;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        if (unleash.isEnabled(FeatureFlags.REGISTRATION_ENABLED.name())) {
            var invalidInputs = InputValidationUtility.validateInputs(dto);
            if (!invalidInputs.isEmpty())
                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
            if (userRepo.existsByUsername(dto.username))
                throw new BadRequestException("Username: '" + dto.username + "' is already taken");
            if (userRepo.existsByEmail(dto.email))
                throw new BadRequestException("Email: '" + dto.email + "' is already registered");
            var sanitizedEmail = SanitizerUtility.sanitizeEmail(dto.email);
            if (userRepo.existsByRealEmail(sanitizedEmail))
                throw new BadRequestException("Alias version of email: '" + dto.email + "' is already registered");
            var user = userRepo.save(toUserModel(dto, sanitizedEmail));
            var shouldVerifyRegisteredEmail = unleash.isEnabled(FeatureFlags.REGISTRATION_EMAIL_VERIFICATION.name());
            user.setEmailVerified(!shouldVerifyRegisteredEmail);
            if (shouldVerifyRegisteredEmail) {
                mailService.sendLinkEmailAsync(user.getEmail(), "Email verification link after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
                return ResponseEntity.ok(Map.of("message", "Registration successful. Please check your email for verification link", "user", user));
            }
            return ResponseEntity.ok(Map.of("message", "Registration successful", "user", user));
        }
        throw new BadRequestException("Registration is currently disabled. Please try again later");
    }

    public UserModel toUserModel(RegistrationDto dto, String sanitizedEmail) {
        return UserModel.builder()
                .username(dto.username)
                .password(passwordEncoder.encode(dto.password))
                .email(dto.email)
                .realEmail(sanitizedEmail)
                .firstName(dto.firstName)
                .middleName(dto.middleName)
                .lastName(dto.lastName)
                .createdBy("SELF")
                .updatedBy("SELF")
                .build();
    }

    public UUID generateEmailVerificationToken(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
            redisService.delete(encryptedEmailVerificationTokenKey);
            redisService.delete(encryptedEmailVerificationTokenMappingKey);
            throw new RuntimeException("Failed to generate email verification token", ex);
        }
    }

    public String getEncryptedEmailVerificationTokenKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
            redisService.delete(Set.of(getEncryptedEmailVerificationTokenKey(user), encryptedEmailVerificationTokenMappingKey));
        } catch (Exception ignored) {
        }
        return Map.of("message", "Email verification successful", "user", MapperUtility.toUserSummaryDto(userRepo.save(user)));
    }

    public String getEncryptedEmailVerificationTokenMappingKey(String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailVerificationTokenStaticConverter.encrypt(EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX + emailVerificationToken);
    }

    public UUID getUserIdFromEncryptedEmailVerificationTokenMappingKey(String encryptedEmailVerificationTokenMappingKey) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
        throw new BadRequestException("Resending email verification link is currently disabled. Please try again later");
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
        throw new BadRequestException("Resending email verification link is currently disabled. Please try again later");
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
        throw new BadRequestException("Resending email verification link is currently disabled. Please try again later");
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

    public String generateOTPForForgotPassword(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = UUID.randomUUID().toString();
        redisService.save(getEncryptedForgotPasswordOtpKey(user), emailOTPForPWDResetRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    public String getEncryptedForgotPasswordOtpKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
        var invalidInputs = InputValidationUtility.validateInputs(dto, "username");
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userRepo.findByUsername(dto.getUsername()).orElseThrow(() -> new BadRequestException("Invalid username"));
        verifyOTPForResetPassword(dto, user);
        user.changePassword(passwordEncoder.encode(dto.password));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    public void verifyOTPForResetPassword(ResetPwdDto dto, UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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
        var invalidInputs = InputValidationUtility.validateInputs(dto, "email");
        if (!invalidInputs.isEmpty()) return ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
        var user = userRepo.findByEmail(dto.getEmail()).orElseThrow(() -> new BadRequestException("Invalid email"));
        verifyOTPForResetPassword(dto, user);
        user.changePassword(passwordEncoder.encode(dto.password));
        user.setUpdatedBy("SELF");
        userRepo.save(user);
        return ResponseEntity.ok(Map.of("message", "Password reset successful"));
    }

    public ResponseEntity<Map<String, Object>> resetPassword(ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var invalidInputs = InputValidationUtility.validateInputs(dto, "usernameOrEmail");
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
        var invalidInputs = InputValidationUtility.validateInputsPasswordAndConfirmPassword(dto);
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
        ValidationUtility.validateEmail(newEmail);
        var user = UserUtility.getCurrentAuthenticatedUser();
        if (user.getEmail().equals(newEmail))
            throw new BadRequestException("New email cannot be same as current email");
        if (userRepo.existsByEmail(newEmail))
            throw new BadRequestException("Email: '" + newEmail + "' is already registered");
        var sanitizedEmail = SanitizerUtility.sanitizeEmail(newEmail);
        if (!user.getRealEmail().equals(sanitizedEmail)) if (userRepo.existsByRealEmail(sanitizedEmail))
            throw new BadRequestException("Alias version of email: '" + newEmail + "' is already registered");
        storeNewEmailForEmailChange(user, newEmail);
        mailService.sendOtpAsync(newEmail, "OTP for email change", generateOTPForEmailChange(user));
        return Map.of("message", "OTP sent to your new email. Please check your email to verify your email change");
    }

    public void storeNewEmailForEmailChange(UserModel user,
                                            String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        redisService.save(getEncryptedEmailChangeKey(user), emailStoreRandomConverter.encrypt(newEmail), RedisService.DEFAULT_TTL);
    }

    public String getEncryptedEmailChangeKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailStoreStaticConverter.encrypt(EMAIL_STORE_PREFIX + user.getId());
    }

    public String generateOTPForEmailChange(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var otp = OTPUtility.generateOtp();
        redisService.save(getEncryptedEmailChangeOTPKey(user), emailOTPForEmailChangeRandomConverter.encrypt(otp), RedisService.DEFAULT_TTL);
        return otp;
    }

    public String getEncryptedEmailChangeOTPKey(UserModel user) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return emailOTPForEmailChangeStaticConverter.encrypt(EMAIL_CHANGE_OTP_PREFIX + user.getId());
    }
}
