package org.vimal.security.v2.utils;

import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.dtos.ResetPwdDto;
import org.vimal.security.v2.exceptions.BadRequestException;

import java.util.Collection;
import java.util.HashSet;

public class InputValidationUtility {
    public static Collection<String> validateInputs(RegistrationDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationUtility.validateUsername(dto.getUsername());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validatePassword(dto.getPassword());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateEmail(dto.getEmail());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateFirstName(dto.getFirstName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateMiddleName(dto.getMiddleName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        try {
            ValidationUtility.validateLastName(dto.getLastName());
        } catch (BadRequestException ex) {
            validationErrors.add(ex.getMessage());
        }
        return validationErrors;
    }

    public static Collection<String> validateInputs(ResetPwdDto dto,
                                                    String type) {
        var validationErrors = validateInputsPasswordAndConfirmPassword(dto);
        switch (type) {
            case "username" -> {
                try {
                    ValidationUtility.validateUsername(dto.getUsername());
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid username");
                }
            }
            case "email" -> {
                try {
                    ValidationUtility.validateEmail(dto.getEmail());
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid email");
                }
            }
            case "usernameOrEmail" -> {
                try {
                    ValidationUtility.validateStringNonNullAndNotEmpty(dto.getUsernameOrEmail(), "Username/email");
                } catch (BadRequestException ex) {
                    validationErrors.add("Invalid username/email");
                }
            }
        }
        try {
            ValidationUtility.validateOTP(dto.getOtp(), "OTP");
        } catch (BadRequestException ex) {
            validationErrors.add("Invalid OTP");
        }
        return validationErrors;
    }

    public static Collection<String> validateInputsPasswordAndConfirmPassword(ResetPwdDto dto) {
        var validationErrors = new HashSet<String>();
        try {
            ValidationUtility.validatePassword(dto.getPassword());
            if (!dto.getPassword().equals(dto.getConfirmPassword()))
                validationErrors.add("New password: '" + dto.getPassword() + "' and confirm password: '" + dto.getConfirmPassword() + "' do not match");
        } catch (BadRequestException ex) {
            validationErrors.add("New " + ex.getMessage());
        }
        return validationErrors;
    }
}
