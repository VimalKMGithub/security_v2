package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.converter.EmailVerificationTokenRandomConverter;
import org.vimal.security.v2.converter.EmailVerificationTokenStaticConverter;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.dtos.UserSummaryDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.CurrentUserUtility;
import org.vimal.security.v2.utils.InputValidationUtility;
import org.vimal.security.v2.utils.MapperUtility;
import org.vimal.security.v2.utils.SanitizerUtility;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final RedisService redisService;
    private final Unleash unleash;
    private final EmailVerificationTokenStaticConverter emailVerificationTokenStaticConverter;
    private final EmailVerificationTokenRandomConverter emailVerificationTokenRandomConverter;

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
            var user = toUserModel(dto, sanitizedEmail);
            var shouldVerifyRegisteredEmail = unleash.isEnabled(FeatureFlags.REGISTRATION_EMAIL_VERIFICATION.name());
            user.setEmailVerified(!shouldVerifyRegisteredEmail);
            if (shouldVerifyRegisteredEmail) {
                mailService.sendLinkEmailAsync(user.getEmail(), "Email verification after registration", "https://godLevelSecurity.com/verifyEmailAfterRegistration?token=" + generateEmailVerificationToken(user));
                return ResponseEntity.ok(Map.of("message", "Registration successful. Please check your email for verification link", "user", userRepo.save(user)));
            }
            return ResponseEntity.ok(Map.of("message", "Registration successful", "user", userRepo.save(user)));
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
        var encryptedEmailVerificationTokenKey = emailVerificationTokenStaticConverter.encrypt(EMAIL_VERIFICATION_TOKEN_PREFIX + user.getId());
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

    public UserSummaryDto getSelfDetails() {
        var user = userRepo.findById(CurrentUserUtility.getCurrentAuthenticatedUser().getId()).orElseThrow(() -> new BadRequestException("Invalid user"));
        return MapperUtility.toUserSummaryDto(user);
    }
}
