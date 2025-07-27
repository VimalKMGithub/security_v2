package org.vimal.security.v2.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.exceptions.BadRequestException;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    private final Unleash unleash;

    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) {
        if (unleash.isEnabled(FeatureFlags.REGISTRATION_ENABLED.name())) {
            return ResponseEntity.ok(Map.of("test", dto));
        }
        throw new BadRequestException("Registration is currently disabled. Please try again later");
    }
}
