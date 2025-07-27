package org.vimal.security.v2.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.InputValidationUtility;
import org.vimal.security.v2.utils.SanitizerUtility;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepo userRepo;
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
        }
        throw new BadRequestException("Registration is currently disabled. Please try again later");
    }
}
