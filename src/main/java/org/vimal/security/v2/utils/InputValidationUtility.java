package org.vimal.security.v2.utils;

import org.vimal.security.v2.dtos.RegistrationDto;
import org.vimal.security.v2.exceptions.BadRequestException;

import java.util.Collection;
import java.util.HashSet;

public class InputValidationUtility {
    public static Collection<String> validateInputs(RegistrationDto dto) {
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
}
