package org.vimal.security.v2.utils;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

public class TOTPUtility {
    private static final TimeBasedOneTimePasswordGenerator totp = new TimeBasedOneTimePasswordGenerator();

    public static String generateBase32Secret() throws NoSuchAlgorithmException {
        var keyGenerator = KeyGenerator.getInstance(totp.getAlgorithm());
        keyGenerator.init(160);
        return new Base32().encodeToString(keyGenerator.generateKey().getEncoded()).replace("=", "");
    }

    public static String generateTOTPUrl(String issuer, String accountName, String base32Secret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30", urlEncode(issuer), urlEncode(accountName), base32Secret, urlEncode(issuer));
    }

    public static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String generateTOTP(String base32Secret) throws InvalidKeyException {
        return String.format("%06d", totp.generateOneTimePassword(decodeBase32Secret(base32Secret), Instant.now()));
    }

    public static boolean verifyTOTP(String base32Secret,
                                     String userInputCode) throws InvalidKeyException {
        return generateTOTP(base32Secret).equals(userInputCode);
    }

    public static SecretKey decodeBase32Secret(String base32Secret) {
        return new SecretKeySpec(new Base32().decode(base32Secret), totp.getAlgorithm());
    }
}
