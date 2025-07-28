package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.GenericRegistrationDto;
import org.vimal.security.v2.dtos.UserSummaryDto;
import org.vimal.security.v2.services.UserService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody GenericRegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.register(dto);
    }

    @GetMapping("/getSelfDetails")
    public ResponseEntity<UserSummaryDto> getSelfDetails() {
        return ResponseEntity.ok(userService.getSelfDetails());
    }

    @PostMapping("/verifyEmail")
    public ResponseEntity<Map<String, Object>> verifyEmail(@RequestParam String emailVerificationToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.verifyEmail(emailVerificationToken));
    }

    @PostMapping("/resend/emailVerification/link/username")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLinkUsername(@RequestParam String username) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.resendEmailVerificationLinkUsername(username));
    }

    @PostMapping("/resend/emailVerification/link/email")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLinkEmail(@RequestParam String email) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.resendEmailVerificationLinkEmail(email));
    }

    @PostMapping("/resend/emailVerification/link")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLink(@RequestParam String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.resendEmailVerificationLink(usernameOrEmail));
    }
}
