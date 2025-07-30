package org.vimal.security.v2.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.services.AdminService;

import java.util.Collection;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @PostMapping("/create/user")
    @PreAuthorize("@PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody UserCreationUpdationDto dto) {
        return adminService.createUser(dto);
    }

    @PostMapping("/create/users")
    @PreAuthorize("@PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Collection<UserCreationUpdationDto> dtos) {
        return adminService.createUsers(dtos);
    }

    @DeleteMapping("/delete/user")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUser(@RequestParam String usernameOrEmail) {
        return adminService.deleteUser(usernameOrEmail);
    }

    @DeleteMapping("/delete/users")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Collection<String> usernamesOrEmails) {
        return adminService.deleteUsers(usernamesOrEmails);
    }
}
