package org.vimal.security.v2.controllers;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.services.AdminService;

import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;
    private final Unleash unleash;

    @PostMapping("/create/user")
    @PreAuthorize("@PreAuth.isAdminOrAbove() or @PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody UserCreationUpdationDto dto) {
        return adminService.createUser(dto);
    }

    @PostMapping("/create/users")
    @PreAuthorize("@PreAuth.isAdminOrAbove() or @PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Collection<UserCreationUpdationDto> dtos) {
        return adminService.createUsers(dtos);
    }

//    @DeleteMapping("/delete/user")
//    @PreAuthorize("@PreAuth.isAdminOrAbove() or @PreAuth.canDeleteUsers()")
//    public ResponseEntity<Map<String, Object>> deleteUser(@RequestParam String usernameOrEmail) {
//        return adminService.deleteUser(usernameOrEmail);
//    }
//
//    @DeleteMapping("/delete/users")
//    @PreAuthorize("@PreAuth.isAdminOrAbove() or @PreAuth.canDeleteUsers()")
//    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Collection<String> usernamesOrEmails) {
//        return adminService.deleteUsers(usernamesOrEmails);
//    }

    @GetMapping("/test")
    public Map<String, Object> test() {
        var is = unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS.name());
        var variant = unleash.getVariant(FeatureFlags.ALLOW_CREATE_USERS.name());

        var payload = variant.getPayload();
//        var value = payload.orElse(null);
        payload.ifPresent(value -> System.out.println(value.getValue()));
        return Map.of(
                "isEnabled", variant.isEnabled(),
                "variant", variant,
                "payload", payload
//                "value", value
        );
    }
}
