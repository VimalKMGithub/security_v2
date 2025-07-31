package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.ResolvedRolesResultDto;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.dtos.UserDeletionResultDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {
    private static final int DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME = 100;
    private static final int DEFAULT_MAX_USERS_TO_READ_AT_A_TIME = 300;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final Unleash unleash;
    private final JWTUtility jwtUtility;

    public ResponseEntity<Map<String, Object>> createUser(UserCreationUpdationDto dto) {
        return createUsers(Set.of(dto));
    }

    public ResponseEntity<Map<String, Object>> createUsers(Collection<UserCreationUpdationDto> dtos) {
        var creator = UserUtility.getCurrentAuthenticatedUserDetails();
        var creatorHighestTopRole = UserUtility.getUserHighestTopRole(creator);
        var variant = unleash.getVariant(FeatureFlags.ALLOW_CREATE_USERS.name());
        if (variant.isEnabled() || SystemRoles.TOP_ROLES.getFirst().equals(creatorHighestTopRole)) {
            if (Objects.isNull(creatorHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name()))
                throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
            if (dtos.isEmpty()) throw new BadRequestException("No users to create");
            if (variant.isEnabled() && variant.getPayload().isPresent()) {
                var maxUsersToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
                if (maxUsersToCreateAtATime < 1) maxUsersToCreateAtATime = DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME;
                if (dtos.size() > maxUsersToCreateAtATime)
                    throw new BadRequestException("Cannot create more than " + maxUsersToCreateAtATime + " users at a time");
            } else if (dtos.size() > DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME)
                throw new BadRequestException("Cannot create more than " + DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME + " users at a time");
            var invalidInputs = new HashSet<String>();
            var roles = new HashSet<String>();
            var duplicateUsernamesInDtos = new HashSet<String>();
            var duplicateEmailsInDtos = new HashSet<String>();
            var usernames = new HashSet<String>();
            var emails = new HashSet<String>();
            var nonNullDtos = new HashSet<UserCreationUpdationDto>();
            dtos.forEach(dto -> {
                if (Objects.isNull(dto)) return;
                var invalidInputsForThisDto = InputValidationUtility.validateInputs(dto);
                if (!invalidInputsForThisDto.isEmpty()) invalidInputs.addAll(invalidInputsForThisDto);
                if (dto.getUsername() != null && ValidationUtility.USERNAME_PATTERN.matcher(dto.getUsername()).matches() && !usernames.add(dto.getUsername()))
                    duplicateUsernamesInDtos.add(dto.getUsername());
                if (dto.getEmail() != null && ValidationUtility.EMAIL_PATTERN.matcher(dto.getEmail()).matches() && !emails.add(dto.getEmail()))
                    duplicateEmailsInDtos.add(dto.getEmail());
                if (dto.getRoles() != null && !dto.getRoles().isEmpty()) {
                    dto.setRoles(dto.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                    if (!dto.getRoles().isEmpty()) roles.addAll(dto.getRoles());
                }
                nonNullDtos.add(dto);
            });
            var mapOfErrors = new HashMap<String, Object>();
            if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
            if (!duplicateUsernamesInDtos.isEmpty())
                mapOfErrors.put("duplicate_usernames_in_request", duplicateUsernamesInDtos);
            if (!duplicateEmailsInDtos.isEmpty())
                mapOfErrors.put("duplicate_emails_in_request", duplicateEmailsInDtos);
            var notAllowedToAssignRoles = validateRolesRestriction(roles, creatorHighestTopRole);
            if (!notAllowedToAssignRoles.isEmpty())
                mapOfErrors.put("not_allowed_to_assign_roles", notAllowedToAssignRoles);
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            var alreadyTakenUsernames = userRepo.findByUsernameIn(usernames).stream().map(UserModel::getUsername).collect(Collectors.toSet());
            var alreadyTakenEmails = userRepo.findByEmailIn(emails).stream().map(UserModel::getEmail).collect(Collectors.toSet());
            var resolvedRolesResult = resolveRoles(roles);
            if (!alreadyTakenUsernames.isEmpty()) mapOfErrors.put("already_taken_usernames", alreadyTakenUsernames);
            if (!alreadyTakenEmails.isEmpty()) mapOfErrors.put("already_taken_emails", alreadyTakenEmails);
            if (!resolvedRolesResult.getMissingRoles().isEmpty())
                mapOfErrors.put("missing_roles", resolvedRolesResult.getMissingRoles());
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            if (nonNullDtos.isEmpty()) return ResponseEntity.badRequest().body(Map.of("message", "No users to create"));
            var resolvedRolesMap = resolvedRolesResult.getRoles().stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
            var newUsers = nonNullDtos.stream().map(dto -> {
                        if (Objects.isNull(dto.getRoles()) || dto.getRoles().isEmpty())
                            return toUserModel(dto, new HashSet<>(), creator.getUserModel());
                        var rolesToAssign = dto.getRoles().stream().map(resolvedRolesMap::get).filter(Objects::nonNull).collect(Collectors.toSet());
                        return toUserModel(dto, rolesToAssign, creator.getUserModel());
                    })
                    .collect(Collectors.toSet());
            return ResponseEntity.ok(Map.of("message", "Users created successfully", "created_users", userRepo.saveAll(newUsers).stream().map(MapperUtility::toUserSummaryToCompanyUsersDto).toList()));
        }
        throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    private Collection<String> validateRolesRestriction(Collection<String> roles,
                                                        String assignerTopRole) {
        var restrictedRoles = new HashSet<String>();
        if (SystemRoles.TOP_ROLES.getFirst().equals(assignerTopRole) || Objects.isNull(roles) || roles.isEmpty())
            return restrictedRoles;
        for (var role : roles) {
            if (SystemRoles.TOP_ROLES.contains(role))
                if (Objects.isNull(assignerTopRole) || SystemRoles.TOP_ROLES.indexOf(role) <= SystemRoles.TOP_ROLES.indexOf(assignerTopRole))
                    restrictedRoles.add(role);
        }
        return restrictedRoles;
    }

    private ResolvedRolesResultDto resolveRoles(Collection<String> roles) {
        if (Objects.isNull(roles) || roles.isEmpty())
            return new ResolvedRolesResultDto(new HashSet<>(), new HashSet<>());
        var foundRoles = roleRepo.findAllById(roles);
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        return new ResolvedRolesResultDto(foundRoles, roles.stream().filter(role -> !foundRoleNames.contains(role)).collect(Collectors.toSet()));
    }

    private UserModel toUserModel(UserCreationUpdationDto dto,
                                  Collection<RoleModel> roles,
                                  UserModel creator) {
        return UserModel.builder()
                .username(dto.getUsername())
                .email(dto.getEmail())
                .realEmail(dto.getEmail())
                .password(passwordEncoder.encode(dto.getPassword()))
                .firstName(dto.getFirstName())
                .middleName(dto.getMiddleName())
                .lastName(dto.getLastName())
                .roles(roles)
                .emailVerified(dto.isEmailVerified())
                .accountEnabled(dto.isAccountEnabled())
                .accountLocked(dto.isAccountLocked())
                .lastLockedAt(dto.isAccountLocked() ? Instant.now() : null)
                .createdBy(creator.getUsername())
                .updatedBy(creator.getUsername())
                .accountDeleted(dto.isAccountDeleted())
                .accountDeletedAt(dto.isAccountDeleted() ? Instant.now() : null)
                .deletedBy(dto.isAccountDeleted() ? creator.getUsername() : null)
                .build();
    }

    public ResponseEntity<Map<String, Object>> deleteUser(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return deleteUsers(Set.of(usernameOrEmail));
    }

    public ResponseEntity<Map<String, Object>> deleteUsers(Collection<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = UserUtility.getUserHighestTopRole(user);
        var deletionResult = deleteUsersResult(usernamesOrEmails, user, userHighestTopRole);
        if (Objects.isNull(deletionResult.getMapOfErrors())) {
            if (!deletionResult.getUsersToDelete().isEmpty()) {
                jwtUtility.revokeTokens(deletionResult.getUsersToDelete());
                userRepo.saveAll(deletionResult.getUsersToDelete());
                return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
            }
            return ResponseEntity.badRequest().body(Map.of("message", "No users to delete"));
        }
        return ResponseEntity.badRequest().body(deletionResult.getMapOfErrors());
    }

    private UserDeletionResultDto deleteUsersResult(Collection<String> usernamesOrEmails,
                                                    UserDetailsImpl user,
                                                    String userHighestTopRole) {
        var variant = unleash.getVariant(FeatureFlags.ALLOW_DELETE_USERS.name());
        if (variant.isEnabled() || SystemRoles.TOP_ROLES.getFirst().equals(userHighestTopRole)) {
            if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name()))
                throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
            if (usernamesOrEmails.isEmpty()) throw new BadRequestException("No users to delete");
            if (variant.isEnabled() && variant.getPayload().isPresent()) {
                var maxUsersToDeleteAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
                if (maxUsersToDeleteAtATime < 1) maxUsersToDeleteAtATime = DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME;
                if (usernamesOrEmails.size() > maxUsersToDeleteAtATime)
                    throw new BadRequestException("Cannot delete more than " + maxUsersToDeleteAtATime + " users at a time");
            } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME)
                throw new BadRequestException("Cannot delete more than " + DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME + " users at a time");
            var invalidInputs = new HashSet<String>();
            var emails = new HashSet<String>();
            var usernames = new HashSet<String>();
            usernamesOrEmails.forEach(identifier -> {
                if (Objects.isNull(identifier)) return;
                if (ValidationUtility.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
                else if (ValidationUtility.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
                else invalidInputs.add(identifier);
            });
            var mapOfErrors = new HashMap<String, Object>();
            if (!invalidInputs.isEmpty()) mapOfErrors.put("invalid_inputs", invalidInputs);
            var ownAccountFoundWithUsernameOrEmail = new HashSet<String>();
            if (usernames.contains(user.getUsername())) ownAccountFoundWithUsernameOrEmail.add(user.getUsername());
            if (emails.contains(user.getUserModel().getEmail()))
                ownAccountFoundWithUsernameOrEmail.add(user.getUserModel().getEmail());
            if (!ownAccountFoundWithUsernameOrEmail.isEmpty())
                mapOfErrors.put("you_cannot_delete_your_own_account_using_this_endpoint", ownAccountFoundWithUsernameOrEmail);
            if (!mapOfErrors.isEmpty()) return new UserDeletionResultDto(mapOfErrors, null, null, null);
            var foundByUsernames = userRepo.findByUsernameIn(usernames);
            var foundByEmails = userRepo.findByEmailIn(emails);
            var usersToDelete = new HashSet<UserModel>();
            var softDeletedUsers = new HashSet<UserModel>();
            var rolesOfUsers = new HashSet<String>();
            var rolesOfSoftDeletedUsers = new HashSet<String>();
            foundByUsernames.forEach(userToDelete -> {
                usernames.remove(userToDelete.getUsername());
                if (userToDelete.isAccountDeleted()) {
                    softDeletedUsers.add(userToDelete);
                    if (!userToDelete.getRoles().isEmpty())
                        userToDelete.getRoles().forEach(role -> rolesOfSoftDeletedUsers.add(role.getRoleName()));
                    return;
                }
                if (!userToDelete.getRoles().isEmpty())
                    userToDelete.getRoles().forEach(role -> rolesOfUsers.add(role.getRoleName()));
                userToDelete.recordAccountDeletion(user.getUsername());
                usersToDelete.add(userToDelete);
            });
            foundByEmails.forEach(userToDelete -> {
                emails.remove(userToDelete.getEmail());
                if (userToDelete.isAccountDeleted()) {
                    softDeletedUsers.add(userToDelete);
                    if (!userToDelete.getRoles().isEmpty())
                        userToDelete.getRoles().forEach(role -> rolesOfSoftDeletedUsers.add(role.getRoleName()));
                    return;
                }
                if (!userToDelete.getRoles().isEmpty())
                    userToDelete.getRoles().forEach(role -> rolesOfUsers.add(role.getRoleName()));
                userToDelete.recordAccountDeletion(user.getUsername());
                usersToDelete.add(userToDelete);
            });
            if (!usernames.isEmpty()) mapOfErrors.put("users_not_found_with_usernames", usernames);
            if (!emails.isEmpty()) mapOfErrors.put("users_not_found_with_emails", emails);
            var notAllowedToDeleteUsersWithRoles = validateRolesRestriction(rolesOfUsers, userHighestTopRole);
            if (!notAllowedToDeleteUsersWithRoles.isEmpty())
                mapOfErrors.put("not_allowed_to_delete_users_with_roles", notAllowedToDeleteUsersWithRoles);
            if (!mapOfErrors.isEmpty()) return new UserDeletionResultDto(mapOfErrors, null, null, null);
            return new UserDeletionResultDto(null, usersToDelete, softDeletedUsers, rolesOfSoftDeletedUsers);
        }
        throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> deleteUserHard(String usernameOrEmail) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        return deleteUsersHard(Set.of(usernameOrEmail));
    }

    public ResponseEntity<Map<String, Object>> deleteUsersHard(Collection<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = UserUtility.getUserHighestTopRole(user);
        var deletionResult = deleteUsersResult(usernamesOrEmails, user, userHighestTopRole);
        if (Objects.isNull(deletionResult.getMapOfErrors())) {
            if (!deletionResult.getRolesOfSoftDeletedUsers().isEmpty()) {
                var notAllowedToDeleteUsersWithRoles = validateRolesRestriction(deletionResult.getRolesOfSoftDeletedUsers(), userHighestTopRole);
                if (!notAllowedToDeleteUsersWithRoles.isEmpty())
                    return ResponseEntity.badRequest().body(Map.of("not_allowed_to_delete_users_with_roles", notAllowedToDeleteUsersWithRoles));
            }
            if (!deletionResult.getSoftDeletedUsers().isEmpty())
                deletionResult.getUsersToDelete().addAll(deletionResult.getSoftDeletedUsers());
            if (!deletionResult.getUsersToDelete().isEmpty()) {
                jwtUtility.revokeTokens(deletionResult.getUsersToDelete());
                userRepo.deleteAll(deletionResult.getUsersToDelete());
                return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
            }
            return ResponseEntity.badRequest().body(Map.of("message", "No users to delete"));
        }
        return ResponseEntity.badRequest().body(deletionResult.getMapOfErrors());
    }

    public ResponseEntity<Map<String, Object>> getUser(String usernameOrEmail) {
        return getUsers(Set.of(usernameOrEmail));
    }

    public ResponseEntity<Map<String, Object>> getUsers(Collection<String> usernamesOrEmails) {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = UserUtility.getUserHighestTopRole(user);
        var variant = unleash.getVariant(FeatureFlags.ALLOW_READ_USERS.name());
        if (variant.isEnabled() || SystemRoles.TOP_ROLES.getFirst().equals(userHighestTopRole)) {
            if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_READ_USERS_BY_USERS_HAVE_PERMISSION_TO_READ_USERS.name()))
                throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
            if (usernamesOrEmails.isEmpty()) throw new BadRequestException("No users to read");
            if (variant.isEnabled() && variant.getPayload().isPresent()) {
                var maxUsersToReadAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
                if (maxUsersToReadAtATime < 1) maxUsersToReadAtATime = DEFAULT_MAX_USERS_TO_READ_AT_A_TIME;
                if (usernamesOrEmails.size() > maxUsersToReadAtATime)
                    throw new BadRequestException("Cannot read more than " + maxUsersToReadAtATime + " users at a time");
            } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_READ_AT_A_TIME)
                throw new BadRequestException("Cannot read more than " + DEFAULT_MAX_USERS_TO_READ_AT_A_TIME + " users at a time");
            var invalidInputs = new HashSet<String>();
            var emails = new HashSet<String>();
            var usernames = new HashSet<String>();
            usernamesOrEmails.forEach(identifier -> {
                if (Objects.isNull(identifier)) return;
                if (ValidationUtility.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
                else if (ValidationUtility.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
                else invalidInputs.add(identifier);
            });
            if (!invalidInputs.isEmpty()) ResponseEntity.badRequest().body(Map.of("invalid_inputs", invalidInputs));
            var foundByUsernames = userRepo.findByUsernameIn(usernames);
            var foundByEmails = userRepo.findByEmailIn(emails);
            var foundByUsernamesUsernames = foundByUsernames.stream().map(UserModel::getUsername).collect(Collectors.toSet());
            var foundByEmailsEmails = foundByEmails.stream().map(UserModel::getEmail).collect(Collectors.toSet());
            usernames.removeAll(foundByUsernamesUsernames);
            emails.removeAll(foundByEmailsEmails);
            var mapOfErrors = new HashMap<String, Object>();
            if (!usernames.isEmpty()) mapOfErrors.put("users_not_found_with_usernames", usernames);
            if (!emails.isEmpty()) mapOfErrors.put("users_not_found_with_emails", emails);
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            foundByUsernames.addAll(foundByEmails);
            return ResponseEntity.ok(Map.of("message", "Users read successfully", "users", foundByUsernames.stream().map(MapperUtility::toUserSummaryToCompanyUsersDto).toList()));
        }
        throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
    }
}
