package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.UserCreationDto;
import org.vimal.security.v2.dtos.UserUpdationDto;
import org.vimal.security.v2.services.AdminService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    private final AdminService adminService;

    @PostMapping("/create/user")
    @PreAuthorize("@PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUser(@RequestBody UserCreationDto dto) {
        return adminService.createUser(dto);
    }

    @PostMapping("/create/users")
    @PreAuthorize("@PreAuth.canCreateUsers()")
    public ResponseEntity<Map<String, Object>> createUsers(@RequestBody Set<UserCreationDto> dtos) {
        return adminService.createUsers(dtos);
    }

    @DeleteMapping("/delete/user")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUser(@RequestParam String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return adminService.deleteUser(usernameOrEmail);
    }

    @DeleteMapping("/delete/users")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUsers(@RequestBody Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return adminService.deleteUsers(usernamesOrEmails);
    }

    @DeleteMapping("/delete/user/hard")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUserHard(@RequestParam String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return adminService.deleteUserHard(usernameOrEmail);
    }

    @DeleteMapping("/delete/users/hard")
    @PreAuthorize("@PreAuth.canDeleteUsers()")
    public ResponseEntity<Map<String, Object>> deleteUsersHard(@RequestBody Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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

    @PutMapping("/update/user")
    @PreAuthorize("@PreAuth.canUpdateUsers()")
    public ResponseEntity<Map<String, Object>> updateUser(@RequestBody UserUpdationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return adminService.updateUser(dto);
    }

    @PutMapping("/update/users")
    @PreAuthorize("@PreAuth.canUpdateUsers()")
    public ResponseEntity<Map<String, Object>> updateUsers(@RequestBody Set<UserUpdationDto> dtos) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return adminService.updateUsers(dtos);
    }
}
