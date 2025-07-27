package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.RegistrationDto;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class UserService {
    public ResponseEntity<Map<String, Object>> register(RegistrationDto dto) {
    }
}
