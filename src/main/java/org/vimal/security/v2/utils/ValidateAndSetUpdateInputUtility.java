package org.vimal.security.v2.utils;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.vimal.security.v2.dtos.UpdationDto;
import org.vimal.security.v2.dtos.UserModificationResultDto;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;

import java.util.HashSet;

public class ValidateAndSetUpdateInputUtility {
    public static UserModificationResultDto validateAndSet(UserModel user,
                                                           UpdationDto dto,
                                                           UserRepo userRepo,
                                                           PasswordEncoder passwordEncoder) {
        var userModificationResult = validateOldPassword(user, dto, passwordEncoder);
        validateAndSetFirstName(user, dto.getFirstName(), userModificationResult);
        validateAndSetMiddleName(user, dto.getMiddleName(), userModificationResult);
        validateAndSetLastName(user, dto.getLastName(), userModificationResult);
        validateAndSetUsername(user, dto.getUsername(), userRepo, userModificationResult);
        return userModificationResult;
    }

    public static UserModificationResultDto validateOldPassword(UserModel user,
                                                                UpdationDto dto,
                                                                PasswordEncoder passwordEncoder) {
        var userModificationResult = new UserModificationResultDto(false, false, new HashSet<>());
        try {
            ValidationUtility.validatePassword(dto.getOldPassword());
            if (!passwordEncoder.matches(dto.getOldPassword(), user.getPassword()))
                userModificationResult.getInvalidInputs().add("Invalid old password");
        } catch (BadRequestException ex) {
            userModificationResult.getInvalidInputs().add("Invalid old password");
        }
        return userModificationResult;
    }

    public static void validateAndSetFirstName(UserModel user,
                                               String firstName,
                                               UserModificationResultDto userModificationResult) {
        if (firstName != null && !firstName.isBlank() && !firstName.equals(user.getFirstName())) {
            try {
                ValidationUtility.validateFirstName(firstName);
                user.setFirstName(firstName);
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
    }

    public static void validateAndSetMiddleName(UserModel user,
                                                String middleName,
                                                UserModificationResultDto userModificationResult) {
        if (middleName != null && !middleName.isBlank() && !middleName.equals(user.getMiddleName())) {
            try {
                ValidationUtility.validateMiddleName(middleName);
                user.setMiddleName(middleName);
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
    }

    public static void validateAndSetLastName(UserModel user,
                                              String lastName,
                                              UserModificationResultDto userModificationResult) {
        if (lastName != null && !lastName.isBlank() && !lastName.equals(user.getLastName())) {
            try {
                ValidationUtility.validateLastName(lastName);
                user.setLastName(lastName);
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
    }

    public static void validateAndSetUsername(UserModel user,
                                              String username,
                                              UserRepo userRepo,
                                              UserModificationResultDto userModificationResult) {
        if (username != null && !username.isBlank() && !username.equals(user.getUsername())) {
            try {
                ValidationUtility.validateUsername(username);
                if (userRepo.existsByUsername(username)) {
                    userModificationResult.getInvalidInputs().add("Username already taken");
                } else {
                    user.setUsername(username);
                    userModificationResult.setModified(true);
                    userModificationResult.setShouldRemoveTokens(true);
                }
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
    }
}
