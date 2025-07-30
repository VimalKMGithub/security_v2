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
        if (dto.getFirstName() != null && !dto.getFirstName().isBlank() && !dto.getFirstName().equals(user.getFirstName())) {
            try {
                ValidationUtility.validateFirstName(dto.getFirstName());
                user.setFirstName(dto.getFirstName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getMiddleName() != null && !dto.getMiddleName().isBlank() && !dto.getMiddleName().equals(user.getMiddleName())) {
            try {
                ValidationUtility.validateMiddleName(dto.getMiddleName());
                user.setMiddleName(dto.getMiddleName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getLastName() != null && !dto.getLastName().isBlank() && !dto.getLastName().equals(user.getLastName())) {
            try {
                ValidationUtility.validateLastName(dto.getLastName());
                user.setLastName(dto.getLastName());
                userModificationResult.setModified(true);
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
        if (dto.getUsername() != null && !dto.getUsername().isBlank() && !dto.getUsername().equals(user.getUsername())) {
            try {
                ValidationUtility.validateUsername(dto.getUsername());
                if (userRepo.existsByUsername(dto.getUsername()))
                    userModificationResult.getInvalidInputs().add("Username already taken");
                else {
                    user.setUsername(dto.getUsername());
                    userModificationResult.setModified(true);
                    userModificationResult.setShouldRemoveTokens(true);
                }
            } catch (BadRequestException ex) {
                userModificationResult.getInvalidInputs().add(ex.getMessage());
            }
        }
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
}
