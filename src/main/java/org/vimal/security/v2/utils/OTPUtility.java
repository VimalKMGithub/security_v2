package org.vimal.security.v2.utils;

import org.vimal.security.v2.exceptions.BadRequestException;

import java.security.SecureRandom;

public class OTPUtility {
    public static final SecureRandom secureRandom = new SecureRandom();
    public static final String DIGITS = "0123456789";
    public static final int DEFAULT_OTP_LENGTH = 6;

    public static String generateOtp() {
        return generateOtp(DEFAULT_OTP_LENGTH);
    }

    private static String generateOtp(int length) {
        if (length < 1) throw new BadRequestException("OTP length must be at least 1");
        var otpChars = new char[length];
        for (int i = 0; i < length; i++) otpChars[i] = DIGITS.charAt(secureRandom.nextInt(DIGITS.length()));
        return new String(otpChars);
    }
}
