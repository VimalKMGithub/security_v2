package org.vimal.security.v2.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.zxing.WriterException;
import lombok.RequiredArgsConstructor;
import org.jose4j.lang.JoseException;
import org.springframework.http.MediaType;
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

    @PostMapping("/MFA/send/email/OTP/toEnableEmailMFA")
    public ResponseEntity<Map<String, String>> sendEmailOTPToEnableEmailMFA() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.sendEmailOTPToEnableEmailMFA());
    }

    @PostMapping("/MFA/verify/email/OTP/toEnableEmailMFA")
    public ResponseEntity<Map<String, String>> verifyEmailOTPToEnableEmailMFA(@RequestParam String otp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyEmailOTPToEnableEmailMFA(otp));
    }

    @PostMapping("/MFA/send/email/OTP/toVerifyEmailMFAToLogin")
    public ResponseEntity<Map<String, String>> sendEmailOTPToVerifyEmailMFAToLogin(@RequestParam String stateToken) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.sendEmailOTPToVerifyEmailMFAToLogin(stateToken));
    }

    @PostMapping("/MFA/verify/email/OTP/toLogin")
    public ResponseEntity<Map<String, Object>> verifyEmailOTPToLogin(@RequestParam String otp,
                                                                     @RequestParam String stateToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyEmailOTPToLogin(otp, stateToken));
    }

    @PostMapping("/MFA/send/email/OTP/toDisableEmailMFA")
    public ResponseEntity<Map<String, String>> sendEmailOTPToDisableEmailMFA() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.sendEmailOTPToDisableEmailMFA());
    }

    @PostMapping("/MFA/verify/email/OTP/toDisableEmailMFA")
    public ResponseEntity<Map<String, String>> verifyEmailOTPToDisableEmailMFA(@RequestParam String otp,
                                                                               @RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyEmailOTPToDisableEmailMFA(otp, password));
    }

    @PostMapping(path = "/MFA/generate/QRCode/toSetupAuthenticatorApp", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> generateQRCodeForAuthenticatorApp() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException, WriterException {
        return ResponseEntity.ok(authenticationService.generateQRCodeForAuthenticatorApp());
    }

    @PostMapping("/MFA/verify/TOTP/toSetupAuthenticatorApp")
    public ResponseEntity<Map<String, String>> verifyTOTPToSetupAuthenticatorApp(@RequestParam String totp) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyTOTPToSetupAuthenticatorApp(totp));
    }

    @PostMapping("/MFA/verify/TOTP/toLogin")
    public ResponseEntity<Map<String, Object>> verifyTOTPToLogin(@RequestParam String totp,
                                                                 @RequestParam String stateToken) throws InvalidAlgorithmParameterException, JoseException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyTOTPToLogin(totp, stateToken));
    }

    @PostMapping("/MFA/verify/TOTP/toDisableAuthenticatorAppMFA")
    public ResponseEntity<Map<String, String>> verifyTOTPToDisableAuthenticatorAppMFA(@RequestParam String totp,
                                                                                      @RequestParam String password) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return ResponseEntity.ok(authenticationService.verifyTOTPToDisableAuthenticatorAppMFA(totp, password));
    }
}
