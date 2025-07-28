package org.vimal.security.v2.utils;

import org.vimal.security.v2.dtos.GenericRegistrationDto;
import org.vimal.security.v2.dtos.GenericResetPwdDto;
import org.vimal.security.v2.exceptions.BadRequestException;

import java.util.Collection;
import java.util.HashSet;

public class InputValidationUtility {
    public static Collection<String> validateInputs(GenericRegistrationDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationUtility.validateUsername(dto.username);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validatePassword(dto.password);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateEmail(dto.email);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateFirstName(dto.firstName);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateMiddleName(dto.middleName);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateLastName(dto.lastName);
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        return validationErrors;
    }

    public static Collection<String> validateInputs(GenericResetPwdDto dto,
                                                    String type) {
        var validationErrors = new HashSet<String>();
        switch (type) {
            case "username" -> {
                try {
                    ValidationUtility.validateUsername(dto.username);
                } catch (BadRequestException ex) {
                    validationErrors.add(ex.getMessage());
                }
            }
            case "email" -> {
                try {
                    ValidationUtility.validateEmail(dto.email);
                } catch (BadRequestException ex) {
                    validationErrors.add(ex.getMessage());
                }
            }
            case "usernameOrEmail" -> {
                try {
                    ValidationUtility.validateStringNonNullAndNotEmpty(dto.usernameOrEmail, "Username/email");
                } catch (BadRequestException ex) {
                    validationErrors.add(ex.getMessage());
                }
            }
        }
        try {
            ValidationUtility.validateOTP(dto.otp, "OTP");
        } catch (BadRequestException ex) {
            validationErrors.add("Invalid OTP");
        }
        try {
            ValidationUtility.validatePassword(dto.password);
            if (!dto.password.equals(dto.confirmPassword))
                validationErrors.add("New password: '" + dto.password + "' and confirm password: '" + dto.confirmPassword + "' do not match");
        } catch (BadRequestException ex) {
            validationErrors.add("New " + ex.getMessage());
        }
        return validationErrors;
    }
}
