package org.vimal.security.v2.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.services.AdminService;

import java.util.Map;
import java.util.Set;

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
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Set<UserCreationUpdationDto> dtos) {
        return adminService.createUsers(dtos);
    }

    @DeleteMapping("/delete/user")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUser(@RequestParam String usernameOrEmail) {
        return adminService.deleteUser(usernameOrEmail);
    }

    @DeleteMapping("/delete/users")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Set<String> usernamesOrEmails) {
        return adminService.deleteUsers(usernamesOrEmails);
    }

    @DeleteMapping("/delete/user/hard")
    @PreAuthorize("@PreAuth.isTopTwoRoles()")
    public ResponseEntity<Map<String, Object>> deleteUserHard(@RequestParam String usernameOrEmail) {
        return adminService.deleteUserHard(usernameOrEmail);
    }

    @DeleteMapping("/delete/users/hard")
    @PreAuthorize("@PreAuth.isTopTwoRoles()")
    public ResponseEntity<Map<String, Object>> deleteUsersHard(@RequestBody Set<String> usernamesOrEmails) {
        return adminService.deleteUsersHard(usernamesOrEmails);
    }

    @GetMapping("/get/user")
    @PreAuthorize("@PreAuth.canReadUsers()")
    public ResponseEntity<Map<String, Object>> getUser(@RequestParam String usernameOrEmail) {
        return adminService.getUser(usernameOrEmail);
    }

    @GetMapping("/get/users")
    @PreAuthorize("@PreAuth.canReadUsers()")
    public ResponseEntity<Map<String, Object>> getUsers(@RequestBody Set<String> usernamesOrEmails) {
        return adminService.getUsers(usernamesOrEmails);
    }
}
