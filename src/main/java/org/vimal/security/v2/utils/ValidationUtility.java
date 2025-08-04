package org.vimal.security.v2.utils;

import org.vimal.security.v2.exceptions.BadRequestException;

import java.util.Objects;
import java.util.regex.Pattern;

public class ValidationUtility {
    public static final Pattern EMAIL_PATTERN = Pattern.compile("^(?=.{1,64}@)[\\p{L}0-9]+([._+-][\\p{L}0-9]+)*@([\\p{L}0-9]+(-[\\p{L}0-9]+)*\\.)+\\p{L}{2,190}$");
    public static final Pattern USERNAME_PATTERN = Pattern.compile("^[\\p{L}0-9_-]{3,100}$");
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,255}$");
    private static final Pattern NAME_PATTERN = Pattern.compile("^[\\p{L} .'-]+$");
    public static final Pattern ROLE_AND_PERMISSION_NAME_PATTERN = Pattern.compile("^[\\p{L}0-9_]+$");
    private static final Pattern UUID_PATTERN = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$");
    private static final Pattern NUMBER_ONLY_PATTERN = Pattern.compile("^[0-9]+$");
    private static final int DEFAULT_OTP_LENGTH = 6;

    public static void validateStringNonNullAndNotEmpty(String value,
                                                        String fieldName) {
        if (Objects.isNull(value)) throw new BadRequestException(fieldName + " cannot be null");
        if (value.isBlank()) throw new BadRequestException(fieldName + " cannot be blank");
    }

    private static void validateStringExactLength(String value,
                                                  String fieldName,
                                                  int length) {
        validateStringNonNullAndNotEmpty(value, fieldName);
        if (value.length() != length)
            throw new BadRequestException(fieldName + " must be exactly " + length + " characters long");
    }

    private static void validateStringMinLength(String value,
                                                String fieldName,
                                                int minLength) {
        validateStringNonNullAndNotEmpty(value, fieldName);
        if (value.length() < minLength)
            throw new BadRequestException(fieldName + " must be at least " + minLength + " characters long");
    }

    private static void validateStringMaxLength(String value,
                                                String fieldName,
                                                int maxLength) {
        validateStringNonNullAndNotEmpty(value, fieldName);
        if (value.length() > maxLength)
            throw new BadRequestException(fieldName + " must be at most " + maxLength + " characters long");
    }

    private static void validateStringLengthRange(String value,
                                                  String fieldName,
                                                  int minLength,
                                                  int maxLength) {
        validateStringNonNullAndNotEmpty(value, fieldName);
        validateStringMinLength(value, fieldName, minLength);
        validateStringMaxLength(value, fieldName, maxLength);
    }

    public static void validateUsername(String username) {
        validateStringLengthRange(username, "Username", 3, 100);
        if (!USERNAME_PATTERN.matcher(username).matches())
            throw new BadRequestException("Username: '" + username + "' is invalid as it can only contain letters, numbers, underscores, and hyphens");
    }

    public static void validatePassword(String password) {
        validateStringLengthRange(password, "Password", 8, 255);
        if (!PASSWORD_PATTERN.matcher(password).matches())
            throw new BadRequestException("Password: '" + password + "' is invalid as it must contain at least one digit, one lowercase letter, one uppercase letter, and one special character");
    }

    public static void validateEmail(String email) {
        validateStringNonNullAndNotEmpty(email, "Email");
        if (!EMAIL_PATTERN.matcher(email).matches())
            throw new BadRequestException("Email: '" + email + "' is of invalid format");
    }

    public static void validateUuid(String uuid,
                                    String fieldName) {
        validateStringNonNullAndNotEmpty(uuid, fieldName);
        if (!UUID_PATTERN.matcher(uuid).matches())
            throw new BadRequestException(fieldName + ": '" + uuid + "' is of invalid format");
    }

    private static void validateStringContainsOnlyNumbers(String value,
                                                          String fieldName) {
        validateStringNonNullAndNotEmpty(value, fieldName);
        if (!NUMBER_ONLY_PATTERN.matcher(value).matches())
            throw new BadRequestException(fieldName + " can only contain numbers");
    }

    private static void validateOTP(String otp,
                                    String fieldName,
                                    int exactLength) {
        validateStringExactLength(otp, fieldName, exactLength);
        validateStringContainsOnlyNumbers(otp, fieldName);
    }

    public static void validateOTP(String otp,
                                   String fieldName) {
        validateOTP(otp, fieldName, DEFAULT_OTP_LENGTH);
    }

    public static void validateFirstName(String firstName) {
        validateStringLengthRange(firstName, "First Name", 1, 50);
        if (!NAME_PATTERN.matcher(firstName).matches())
            throw new BadRequestException("First Name: '" + firstName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
    }

    public static void validateMiddleName(String middleName) {
        if (Objects.isNull(middleName)) return;
        validateStringLengthRange(middleName, "Middle Name", 1, 50);
        if (!NAME_PATTERN.matcher(middleName).matches())
            throw new BadRequestException("Middle Name: '" + middleName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
    }

    public static void validateLastName(String lastName) {
        if (Objects.isNull(lastName)) return;
        validateStringLengthRange(lastName, "Last Name", 1, 50);
        if (!NAME_PATTERN.matcher(lastName).matches())
            throw new BadRequestException("Last Name: '" + lastName + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
    }

    public static void validateRoleAndPermissionName(String name) {
        validateStringNonNullAndNotEmpty(name, "Role/Permission Name");
        if (!ROLE_AND_PERMISSION_NAME_PATTERN.matcher(name).matches())
            throw new BadRequestException("Role/Permission Name: '" + name + "' is invalid as it can only contain letters, numbers, and underscores");
    }

    public static void validateDescription(String description) {
        if (Objects.isNull(description)) return;
        if (description.isBlank()) throw new BadRequestException("Description cannot be blank if provided");
        validateStringMaxLength(description, "Description", 255);
        if (!NAME_PATTERN.matcher(description).matches())
            throw new BadRequestException("Description: '" + description + "' is invalid as it can only contain letters, spaces, periods, apostrophes, and hyphens");
    }
}
