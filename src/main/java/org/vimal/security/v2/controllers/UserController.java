package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.vimal.security.v2.dtos.*;
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

    @PostMapping("/resend/emailVerification/link")
    public ResponseEntity<Map<String, String>> resendEmailVerificationLink(@RequestParam String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.resendEmailVerificationLink(usernameOrEmail));
    }

    @PostMapping("/forgot/password")
    public ResponseEntity<Map<String, Object>> forgotPassword(@RequestParam String usernameOrEmail) {
        return userService.forgotPassword(usernameOrEmail);
    }

    @PostMapping("/forgot/password/methodSelection")
    public ResponseEntity<Map<String, String>> forgotPasswordMethodSelection(@RequestParam String usernameOrEmail,
                                                                             @RequestParam String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.forgotPasswordMethodSelection(usernameOrEmail, method));
    }

    @PostMapping("/reset/password")
    public ResponseEntity<Map<String, Object>> resetPassword(@RequestBody ResetPwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.resetPassword(dto);
    }

    @PostMapping("/change/password")
    public ResponseEntity<Map<String, Object>> changePassword(@RequestBody ChangePwdDto dto) {
        return userService.changePassword(dto);
    }

    @PostMapping("/change/password/methodSelection")
    public ResponseEntity<Map<String, String>> changePasswordMethodSelection(@RequestParam String method) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.changePasswordMethodSelection(method));
    }

    @PostMapping("/verify/change/password")
    public ResponseEntity<Map<String, Object>> verifyChangePassword(@RequestBody ChangePwdDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.verifyChangePassword(dto);
    }

    @PostMapping("/email/change/request")
    public ResponseEntity<Map<String, String>> emailChangeRequest(@RequestParam String newEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.emailChangeRequest(newEmail));
    }

    @PostMapping("/verify/email/change")
    public ResponseEntity<Map<String, Object>> verifyEmailChange(@RequestParam String newEmailOtp,
                                                                 @RequestParam String oldEmailOtp,
                                                                 @RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.verifyEmailChange(newEmailOtp, oldEmailOtp, password));
    }

    @DeleteMapping("/delete/account/password")
    public ResponseEntity<Map<String, Object>> deleteAccountPassword(@RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.deleteAccountPassword(password);
    }

    @PostMapping("/send/OTP/toDelete/account")
    public ResponseEntity<Map<String, String>> sendOTPToDeleteAccount() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.sendOTPToDeleteAccount());
    }

    @DeleteMapping("/verify/OTP/toDelete/account")
    public ResponseEntity<Map<String, String>> verifyOTPToDeleteAccount(@RequestParam String otp,
                                                                        @RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.verifyOTPToDeleteAccount(otp, password));
    }

    @DeleteMapping("/verify/TOTP/toDelete/account")
    public ResponseEntity<Map<String, String>> verifyTOTPToDeleteAccount(@RequestParam String totp,
                                                                         @RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(userService.verifyTOTPToDeleteAccount(totp, password));
    }

    @PutMapping("/update/details")
    public ResponseEntity<Map<String, Object>> updateDetails(@RequestBody UpdationDto dto) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return userService.updateDetails(dto);
    }
}
