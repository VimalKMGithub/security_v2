package org.vimal.security.v2.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.InputValidationUtility;
import org.vimal.security.v2.utils.SanitizerUtility;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    private static final String EMAIL_VERIFICATION_TOKEN_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN:";
    private static final String EMAIL_VERIFICATION_TOKEN_MAPPING_PREFIX = "SECURITY_V2_EMAIL_VERIFICATION_TOKEN_MAPPING:";
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final MailService mailService;
    private final Unleash unleash;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) {
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
//            if (shouldVerifyRegisteredEmail) mailService.sendVerificationEmail(user);
            userRepo.save(user);
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
}
