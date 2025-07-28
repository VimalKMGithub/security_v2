package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.dtos.ResetPwdDto;
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
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegistrationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
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

    @PostMapping("/forgot/password/username")
    public ResponseEntity<Map<String, String>> forgotPasswordUsername(@RequestParam String username) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.forgotPasswordUsername(username));
    }

    @PostMapping("/forgot/password/email")
    public ResponseEntity<Map<String, String>> forgotPasswordEmail(@RequestParam String email) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.forgotPasswordEmail(email));
    }

    @PostMapping("/forgot/password")
    public ResponseEntity<Map<String, String>> forgotPassword(@RequestParam String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.forgotPassword(usernameOrEmail));
    }

    @PostMapping("/reset/password/username")
    public ResponseEntity<Map<String, Object>> resetPasswordUsername(@RequestBody ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.resetPasswordUsername(dto);
    }

    @PostMapping("/reset/password/email")
    public ResponseEntity<Map<String, Object>> resetPasswordEmail(@RequestBody ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.resetPasswordEmail(dto);
    }

    @PostMapping("/reset/password")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.resetPassword(dto);
    }
}
