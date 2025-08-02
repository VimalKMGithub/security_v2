package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.vimal.security.v2.services.AuthenticationService;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestParam String usernameOrEmail,
                                                     @RequestParam String password) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.login(usernameOrEmail, password));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.logout());
    }

    @PostMapping("/refresh/accessToken")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(@RequestParam String refreshToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.refreshAccessToken(refreshToken));
    }

    @PostMapping("/revoke/accessToken")
    public ResponseEntity<Map<String, String>> revokeAccessToken() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.revokeAccessToken());
    }

    @PostMapping("/revoke/refreshToken")
    public ResponseEntity<Map<String, String>> revokeRefreshToken(@RequestParam String refreshToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.revokeRefreshToken(refreshToken));
    }

    @PostMapping("/MFA/requestTo/toggle")
    public ResponseEntity<Object> requestToToggleMFA(@RequestParam String type,
                                                     @RequestParam String toggle) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, WriterException {
        return authenticationService.requestToToggleMFA(type, toggle);
    }

    @PostMapping("/MFA/verify/toggle")
    public ResponseEntity<Map<String, String>> verifyToggleMFA(@RequestParam String type,
                                                               @RequestParam String toggle,
                                                               @RequestParam String otpTotp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyToggleMFA(type, toggle, otpTotp));
    }

    @PostMapping("/MFA/requestTo/login")
    public ResponseEntity<Map<String, String>> requestToLoginMFA(@RequestParam String type,
                                                                 @RequestParam String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.requestToLoginMFA(type, stateToken));
    }

    @PostMapping("/MFA/verify/MFA/toLogin")
    public ResponseEntity<Map<String, Object>> verifyMFAForLogin(@RequestParam String type,
                                                                 @RequestParam String stateToken,
                                                                 @RequestParam String otpTotp) {
    }

    @PostMapping("/MFA/verify/email/OTP/toLogin")
    public ResponseEntity<Map<String, Object>> verifyEmailOTPToLogin(@RequestParam String otp,
                                                                     @RequestParam String stateToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyEmailOTPToLogin(otp, stateToken));
    }

    @PostMapping("/MFA/verify/TOTP/toLogin")
    public ResponseEntity<Map<String, Object>> verifyTOTPToLogin(@RequestParam String totp,
                                                                 @RequestParam String stateToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyTOTPToLogin(totp, stateToken));
    }
}
