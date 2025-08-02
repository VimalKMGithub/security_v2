package org.vimal.security.v2.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.*;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.impls.UserDetailsImpl;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.JWTUtility;
import org.vimal.security.v2.utils.MapperUtility;
import org.vimal.security.v2.utils.UserUtility;
import org.vimal.security.v2.utils.ValidationUtility;

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
    private static final int DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME = 100;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final Unleash unleash;
    private final JWTUtility jwtUtility;

    public ResponseEntity<Map<String, Object>> createUsers(Set<UserCreationDto> dtos) {
        var creator = UserUtility.getCurrentAuthenticatedUserDetails();
        var creatorHighestTopRole = getUserHighestTopRole(creator);
        var variant = unleash.getVariant(FeatureFlags.ALLOW_CREATE_USERS.name());
        if (entryCheck(variant, creatorHighestTopRole)) {
            checkUserCanCreateUsers(creatorHighestTopRole);
            validateDtosSizeForUsersCreation(variant, dtos);
            var userCreationResult = validateInputs(dtos);
            var mapOfErrors = errorsStuffingIfAny(userCreationResult, creatorHighestTopRole);
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            var alreadyTakenUsernames = userRepo.findByUsernameIn(userCreationResult.getUsernames()).stream().map(UserModel::getUsername).collect(Collectors.toSet());
            var alreadyTakenEmails = userRepo.findByEmailIn(userCreationResult.getEmails()).stream().map(UserModel::getEmail).collect(Collectors.toSet());
            var resolvedRolesResult = resolveRoles(userCreationResult.getRoles());
            if (!alreadyTakenUsernames.isEmpty()) mapOfErrors.put("already_taken_usernames", alreadyTakenUsernames);
            if (!alreadyTakenEmails.isEmpty()) mapOfErrors.put("already_taken_emails", alreadyTakenEmails);
            if (!resolvedRolesResult.getMissingRoles().isEmpty())
                mapOfErrors.put("missing_roles", resolvedRolesResult.getMissingRoles());
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            if (dtos.isEmpty()) return ResponseEntity.ok(Map.of("message", "No users to create"));
            var resolvedRolesMap = resolvedRolesResult.getRoles().stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
            var newUsers = dtos.stream().map(dto -> {
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

    private String getUserHighestTopRole(UserDetailsImpl userDetails) {
        return getUserHighestTopRole(userDetails.getAuthorities());
    }

    private String getUserHighestTopRole(Set<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .filter(SystemRoles.TOP_ROLES::contains)
                .min(Comparator.comparingInt(SystemRoles.TOP_ROLES::indexOf))
                .orElse(null);
    }

    private boolean entryCheck(Variant variant,
                               String userHighestTopRole) {
        return variant.isEnabled() || SystemRoles.TOP_ROLES.getFirst().equals(userHighestTopRole);
    }

    private void checkUserCanCreateUsers(String userHighestTopRole) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name()))
            throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
    }

    private void validateDtosSizeForUsersCreation(Variant variant,
                                                  Set<UserCreationDto> dtos) {
        if (dtos.isEmpty()) throw new BadRequestException("No users to create");
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            var maxUsersToCreateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToCreateAtATime < 1) maxUsersToCreateAtATime = DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME;
            if (dtos.size() > maxUsersToCreateAtATime)
                throw new BadRequestException("Cannot create more than " + maxUsersToCreateAtATime + " users at a time");
        } else if (dtos.size() > DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME)
            throw new BadRequestException("Cannot create more than " + DEFAULT_MAX_USERS_TO_CREATE_AT_A_TIME + " users at a time");
    }

    private UserCreationResultDto validateInputs(Set<UserCreationDto> dtos) {
        var invalidInputs = new HashSet<String>();
        var roles = new HashSet<String>();
        var duplicateUsernamesInDtos = new HashSet<String>();
        var duplicateEmailsInDtos = new HashSet<String>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        dtos.remove(null);
        dtos.forEach(dto -> {
            var invalidInputsForThisDto = UserUtility.validateInputs(dto);
            if (!invalidInputsForThisDto.isEmpty()) invalidInputs.addAll(invalidInputsForThisDto);
            if (dto.getUsername() != null && ValidationUtility.USERNAME_PATTERN.matcher(dto.getUsername()).matches() && !usernames.add(dto.getUsername()))
                duplicateUsernamesInDtos.add(dto.getUsername());
            if (dto.getEmail() != null && ValidationUtility.EMAIL_PATTERN.matcher(dto.getEmail()).matches() && !emails.add(dto.getEmail()))
                duplicateEmailsInDtos.add(dto.getEmail());
            if (dto.getRoles() != null && !dto.getRoles().isEmpty()) {
                dto.setRoles(dto.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!dto.getRoles().isEmpty()) roles.addAll(dto.getRoles());
            }
        });
        return new UserCreationResultDto(invalidInputs, usernames, emails, duplicateUsernamesInDtos, duplicateEmailsInDtos, roles);
    }

    private Map<String, Object> errorsStuffingIfAny(UserCreationResultDto userCreationResult,
                                                    String userHighestTopRole) {
        var mapOfErrors = new HashMap<String, Object>();
        if (!userCreationResult.getInvalidInputs().isEmpty())
            mapOfErrors.put("invalid_inputs", userCreationResult.getInvalidInputs());
        if (!userCreationResult.getDuplicateUsernamesInDtos().isEmpty())
            mapOfErrors.put("duplicate_usernames_in_request", userCreationResult.getDuplicateUsernamesInDtos());
        if (!userCreationResult.getDuplicateEmailsInDtos().isEmpty())
            mapOfErrors.put("duplicate_emails_in_request", userCreationResult.getDuplicateEmailsInDtos());
        var notAllowedToAssignRoles = validateRolesRestriction(userCreationResult.getRoles(), userHighestTopRole);
        if (!notAllowedToAssignRoles.isEmpty())
            mapOfErrors.put("not_allowed_to_assign_roles", notAllowedToAssignRoles);
        return mapOfErrors;
    }

    private Set<String> validateRolesRestriction(Set<String> roles,
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

    private ResolvedRolesResultDto resolveRoles(Set<String> roles) {
        if (Objects.isNull(roles) || roles.isEmpty())
            return new ResolvedRolesResultDto(new HashSet<>(), new HashSet<>());
        var foundRoles = roleRepo.findAllById(roles);
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        return new ResolvedRolesResultDto(foundRoles, roles.stream().filter(role -> !foundRoleNames.contains(role)).collect(Collectors.toSet()));
    }

    private UserModel toUserModel(UserCreationDto dto,
                                  Set<RoleModel> roles,
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
                .lastAccountDeletedAt(dto.isAccountDeleted() ? Instant.now() : null)
                .lastDeletedUndeletedBy(dto.isAccountDeleted() ? creator.getUsername() : null)
                .build();
    }

    public ResponseEntity<Map<String, Object>> deleteUsers(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = getUserHighestTopRole(user);
        var deletionResult = deleteUsersResult(usernamesOrEmails, user, userHighestTopRole);
        if (deletionResult.getMapOfErrors().isEmpty()) {
            if (!deletionResult.getUsersToDelete().isEmpty()) {
                jwtUtility.revokeTokens(deletionResult.getUsersToDelete());
                userRepo.saveAll(deletionResult.getUsersToDelete());
                return ResponseEntity.ok(Map.of("message", "Users deleted successfully"));
            }
            return ResponseEntity.badRequest().body(Map.of("message", "No users to delete"));
        }
        return ResponseEntity.badRequest().body(deletionResult.getMapOfErrors());
    }

    private UserDeletionResultDto deleteUsersResult(Set<String> usernamesOrEmails,
                                                    UserDetailsImpl user,
                                                    String userHighestTopRole) {
        var variant = unleash.getVariant(FeatureFlags.ALLOW_DELETE_USERS.name());
        if (entryCheck(variant, userHighestTopRole)) {
            checkUserCanDeleteUsers(userHighestTopRole);
            validateInputsSizeForUsersDeletion(variant, usernamesOrEmails);
            var userDeletionInputResult = validateInput(usernamesOrEmails, user);
            var mapOfErrors = errorsStuffingIfAnyInInput(userDeletionInputResult);
            if (!mapOfErrors.isEmpty()) return new UserDeletionResultDto(mapOfErrors, null, null, null);
            return getUserDeletionResult(userDeletionInputResult, user, userHighestTopRole);
        }
        throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
    }

    private void checkUserCanDeleteUsers(String userHighestTopRole) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name()))
            throw new ServiceUnavailableException("Deletion of users is currently disabled. Please try again later");
    }

    private void validateInputsSizeForUsersDeletion(Variant variant,
                                                    Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestException("No users to delete");
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            var maxUsersToDeleteAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToDeleteAtATime < 1) maxUsersToDeleteAtATime = DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME;
            if (usernamesOrEmails.size() > maxUsersToDeleteAtATime)
                throw new BadRequestException("Cannot delete more than " + maxUsersToDeleteAtATime + " users at a time");
        } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME)
            throw new BadRequestException("Cannot delete more than " + DEFAULT_MAX_USERS_TO_DELETE_AT_A_TIME + " users at a time");
    }

    private UserDeletionReadInputResultDto validateInput(Set<String> usernamesOrEmails,
                                                         UserDetailsImpl user) {
        var invalidInputs = new HashSet<String>();
        var emails = new HashSet<String>();
        var usernames = new HashSet<String>();
        var ownUserInInputs = new HashSet<String>();
        usernamesOrEmails.remove(null);
        usernamesOrEmails.forEach(identifier -> {
            if (ValidationUtility.USERNAME_PATTERN.matcher(identifier).matches()) usernames.add(identifier);
            else if (ValidationUtility.EMAIL_PATTERN.matcher(identifier).matches()) emails.add(identifier);
            else invalidInputs.add(identifier);
        });
        if (usernames.contains(user.getUsername())) ownUserInInputs.add(user.getUsername());
        if (usernames.contains(user.getUserModel().getEmail())) ownUserInInputs.add(user.getUserModel().getEmail());
        return new UserDeletionReadInputResultDto(invalidInputs, usernames, emails, ownUserInInputs);
    }

    private Map<String, Object> errorsStuffingIfAnyInInput(UserDeletionReadInputResultDto userDeletionInputResult) {
        var mapOfErrors = new HashMap<String, Object>();
        if (!userDeletionInputResult.getInvalidInputs().isEmpty())
            mapOfErrors.put("invalid_inputs", userDeletionInputResult.getInvalidInputs());
        if (!userDeletionInputResult.getOwnUserInInputs().isEmpty())
            mapOfErrors.put("you_cannot_delete_your_own_account_using_this_endpoint", userDeletionInputResult.getOwnUserInInputs());
        return mapOfErrors;
    }

    private UserDeletionResultDto getUserDeletionResult(UserDeletionReadInputResultDto userDeletionInputResult,
                                                        UserDetailsImpl user,
                                                        String userHighestTopRole) {
        var foundByUsernames = userRepo.findByUsernameIn(userDeletionInputResult.getUsernames());
        var foundByEmails = userRepo.findByEmailIn(userDeletionInputResult.getEmails());
        var usersToDelete = new HashSet<UserModel>();
        var softDeletedUsers = new HashSet<UserModel>();
        var rolesOfUsers = new HashSet<String>();
        var rolesOfSoftDeletedUsers = new HashSet<String>();
        foundByUsernames.forEach(userToDelete -> {
            userDeletionInputResult.getUsernames().remove(userToDelete.getUsername());
            if (userToDelete.isAccountDeleted()) {
                softDeletedUsers.add(userToDelete);
                if (!userToDelete.getRoles().isEmpty())
                    userToDelete.getRoles().forEach(role -> rolesOfSoftDeletedUsers.add(role.getRoleName()));
                return;
            }
            if (!userToDelete.getRoles().isEmpty())
                userToDelete.getRoles().forEach(role -> rolesOfUsers.add(role.getRoleName()));
            userToDelete.recordAccountDeletion(true, user.getUsername());
            usersToDelete.add(userToDelete);
        });
        foundByEmails.forEach(userToDelete -> {
            userDeletionInputResult.getEmails().remove(userToDelete.getEmail());
            if (userToDelete.isAccountDeleted()) {
                softDeletedUsers.add(userToDelete);
                if (!userToDelete.getRoles().isEmpty())
                    userToDelete.getRoles().forEach(role -> rolesOfSoftDeletedUsers.add(role.getRoleName()));
                return;
            }
            if (!userToDelete.getRoles().isEmpty())
                userToDelete.getRoles().forEach(role -> rolesOfUsers.add(role.getRoleName()));
            userToDelete.recordAccountDeletion(true, user.getUsername());
            usersToDelete.add(userToDelete);
        });
        return new UserDeletionResultDto(errorsStuffingIfAnyInInput(userDeletionInputResult, rolesOfUsers, userHighestTopRole), usersToDelete, softDeletedUsers, rolesOfSoftDeletedUsers);
    }

    private Map<String, Object> errorsStuffingIfAnyInInput(UserDeletionReadInputResultDto userDeletionInputResult,
                                                           Set<String> rolesOfUsers,
                                                           String userHighestTopRole) {
        var mapOfErrors = new HashMap<String, Object>();
        if (!userDeletionInputResult.getUsernames().isEmpty())
            mapOfErrors.put("users_not_found_with_usernames", userDeletionInputResult.getUsernames());
        if (!userDeletionInputResult.getEmails().isEmpty())
            mapOfErrors.put("users_not_found_with_emails", userDeletionInputResult.getEmails());
        var notAllowedToDeleteUsersWithRoles = validateRolesRestriction(rolesOfUsers, userHighestTopRole);
        if (!notAllowedToDeleteUsersWithRoles.isEmpty())
            mapOfErrors.put("not_allowed_to_delete_users_with_roles", notAllowedToDeleteUsersWithRoles);
        return mapOfErrors;
    }

    public ResponseEntity<Map<String, Object>> deleteUsersHard(Set<String> usernamesOrEmails) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = getUserHighestTopRole(user);
        if (entryCheck(unleash.getVariant(FeatureFlags.ALLOW_HARD_DELETE_USERS.name()), userHighestTopRole)) {
            checkUserCanHardDeleteUsers(userHighestTopRole);
            var deletionResult = deleteUsersResult(usernamesOrEmails, user, userHighestTopRole);
            if (deletionResult.getMapOfErrors().isEmpty()) {
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
        throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
    }

    private void checkUserCanHardDeleteUsers(String userHighestTopRole) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_HARD_DELETE_USERS_BY_USERS_HAVE_PERMISSION_TO_DELETE_USERS.name()))
            throw new ServiceUnavailableException("Hard deletion of users is currently disabled. Please try again later");
    }

    public ResponseEntity<Map<String, Object>> getUsers(Set<String> usernamesOrEmails) {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = getUserHighestTopRole(user);
        var variant = unleash.getVariant(FeatureFlags.ALLOW_READ_USERS.name());
        if (entryCheck(variant, userHighestTopRole)) {
            checkUserCanReadUsers(userHighestTopRole);
            validateInputsSizeForUsersToRead(variant, usernamesOrEmails);
            var userReadsInputResult = validateInput(usernamesOrEmails, user);
            var mapOfErrors = errorsStuffingIfAnyInInput(userReadsInputResult);
            if (!mapOfErrors.isEmpty() && mapOfErrors.containsKey("invalid_inputs"))
                return ResponseEntity.badRequest().body(Map.of("invalid_inputs", mapOfErrors.get("invalid_inputs")));
            var foundByUsernames = userRepo.findByUsernameIn(userReadsInputResult.getUsernames());
            var foundByEmails = userRepo.findByEmailIn(userReadsInputResult.getEmails());
            var foundByUsernamesUsernames = foundByUsernames.stream().map(UserModel::getUsername).collect(Collectors.toSet());
            var foundByEmailsEmails = foundByEmails.stream().map(UserModel::getEmail).collect(Collectors.toSet());
            userReadsInputResult.getUsernames().removeAll(foundByUsernamesUsernames);
            userReadsInputResult.getEmails().removeAll(foundByEmailsEmails);
            mapOfErrors = new HashMap<>();
            if (!userReadsInputResult.getUsernames().isEmpty())
                mapOfErrors.put("users_not_found_with_usernames", userReadsInputResult.getUsernames());
            if (!userReadsInputResult.getEmails().isEmpty())
                mapOfErrors.put("users_not_found_with_emails", userReadsInputResult.getEmails());
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            foundByUsernames.addAll(foundByEmails);
            return ResponseEntity.ok(Map.of("message", "Users read successfully", "users", foundByUsernames.stream().map(MapperUtility::toUserSummaryToCompanyUsersDto).toList()));
        }
        throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
    }

    private void checkUserCanReadUsers(String userHighestTopRole) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_READ_USERS_BY_USERS_HAVE_PERMISSION_TO_READ_USERS.name()))
            throw new ServiceUnavailableException("Reading users is currently disabled. Please try again later");
    }

    private void validateInputsSizeForUsersToRead(Variant variant,
                                                  Set<String> usernamesOrEmails) {
        if (usernamesOrEmails.isEmpty()) throw new BadRequestException("No users to read");
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            var maxUsersToReadAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToReadAtATime < 1) maxUsersToReadAtATime = DEFAULT_MAX_USERS_TO_READ_AT_A_TIME;
            if (usernamesOrEmails.size() > maxUsersToReadAtATime)
                throw new BadRequestException("Cannot read more than " + maxUsersToReadAtATime + " users at a time");
        } else if (usernamesOrEmails.size() > DEFAULT_MAX_USERS_TO_READ_AT_A_TIME)
            throw new BadRequestException("Cannot read more than " + DEFAULT_MAX_USERS_TO_READ_AT_A_TIME + " users at a time");
    }

    public ResponseEntity<Map<String, Object>> updateUsers(Set<UserUpdationDto> dtos) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, JsonProcessingException {
        var user = UserUtility.getCurrentAuthenticatedUserDetails();
        var userHighestTopRole = getUserHighestTopRole(user);
        var variant = unleash.getVariant(FeatureFlags.ALLOW_UPDATE_USERS.name());
        if (entryCheck(variant, userHighestTopRole)) {
            checkUserCanUpdateUsers(userHighestTopRole);
            validateDtosSizeForUsersToUpdate(variant, dtos);
            var userUpdationResult = validateInputsForUserUpdation(dtos);
            var mapOfErrors = errorsStuffingIfAnyInUserUpdation(userUpdationResult, user, userHighestTopRole);
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            var conflictingUsernamesEmailsResult = getConflictingUsernamesEmails(userUpdationResult, dtos);
            mapOfErrors = errorsStuffingIfAnyInUserUpdation(conflictingUsernamesEmailsResult);
            if (!mapOfErrors.isEmpty()) return ResponseEntity.badRequest().body(mapOfErrors);
            var userUpdationWithNewDetailsResult = getResultOfUserUpdationWithNewDetails(userUpdationResult, dtos, user, userHighestTopRole);
            if (!userUpdationWithNewDetailsResult.getMapOfErrors().isEmpty())
                return ResponseEntity.badRequest().body(userUpdationWithNewDetailsResult.getMapOfErrors());
            if (userUpdationWithNewDetailsResult.getUpdatedUsers().isEmpty() && userUpdationWithNewDetailsResult.getUsersToWhichWeHaveToRevokeTokens().isEmpty())
                return ResponseEntity.ok(Map.of("message", "No users updated"));
            if (!userUpdationWithNewDetailsResult.getUsersToWhichWeHaveToRevokeTokens().isEmpty()) {
                jwtUtility.revokeTokens(userUpdationWithNewDetailsResult.getUsersToWhichWeHaveToRevokeTokens());
                userUpdationWithNewDetailsResult.getUpdatedUsers().addAll(userUpdationWithNewDetailsResult.getUsersToWhichWeHaveToRevokeTokens());
            }
            return ResponseEntity.ok(Map.of("message", "Users updated successfully", "updated_users", userRepo.saveAll(userUpdationWithNewDetailsResult.getUpdatedUsers()).stream().map(MapperUtility::toUserSummaryToCompanyUsersDto).toList()));
        }
        throw new ServiceUnavailableException("Updating users is currently disabled. Please try again later");
    }

    private void checkUserCanUpdateUsers(String userHighestTopRole) {
        if (Objects.isNull(userHighestTopRole) && !unleash.isEnabled(FeatureFlags.ALLOW_UPDATE_USERS_BY_USERS_HAVE_PERMISSION_TO_UPDATE_USERS.name()))
            throw new ServiceUnavailableException("Updating users is currently disabled. Please try again later");
    }

    private void validateDtosSizeForUsersToUpdate(Variant variant,
                                                  Set<UserUpdationDto> dtos) {
        if (dtos.isEmpty()) throw new BadRequestException("No users to update");
        if (variant.isEnabled() && variant.getPayload().isPresent()) {
            var maxUsersToUpdateAtATime = Integer.parseInt(Objects.requireNonNull(variant.getPayload().get().getValue()));
            if (maxUsersToUpdateAtATime < 1) maxUsersToUpdateAtATime = DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME;
            if (dtos.size() > maxUsersToUpdateAtATime)
                throw new BadRequestException("Cannot update more than " + maxUsersToUpdateAtATime + " users at a time");
        } else if (dtos.size() > DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME)
            throw new BadRequestException("Cannot update more than " + DEFAULT_MAX_USERS_TO_UPDATE_AT_A_TIME + " users at a time");
    }

    private UserUpdationResultDto validateInputsForUserUpdation(Set<UserUpdationDto> dtos) {
        var invalidOldUsernames = new HashSet<String>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
        var roles = new HashSet<String>();
        var duplicateUsernamesInDtos = new HashSet<String>();
        var duplicateEmailsInDtos = new HashSet<String>();
        var oldUsernames = new HashSet<String>();
        var duplicateOldUsernames = new HashSet<String>();
        var invalidInputs = new HashSet<String>();
        dtos.remove(null);
        dtos.forEach(dto -> {
            try {
                ValidationUtility.validateUsername(dto.getOldUsername());
                if (!oldUsernames.add(dto.getOldUsername())) duplicateOldUsernames.add(dto.getOldUsername());
            } catch (BadRequestException ex) {
                invalidOldUsernames.add(dto.getOldUsername());
            }
            if (dto.getUsername() != null) {
                try {
                    ValidationUtility.validateUsername(dto.getUsername());
                    if (!usernames.add(dto.getUsername())) duplicateUsernamesInDtos.add(dto.getUsername());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getEmail() != null) {
                try {
                    ValidationUtility.validateEmail(dto.getEmail());
                    if (!emails.add(dto.getEmail())) duplicateEmailsInDtos.add(dto.getEmail());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getPassword() != null) {
                try {
                    ValidationUtility.validatePassword(dto.getPassword());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getFirstName() != null) {
                try {
                    ValidationUtility.validateFirstName(dto.getFirstName());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getMiddleName() != null) {
                try {
                    ValidationUtility.validateMiddleName(dto.getMiddleName());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getLastName() != null) {
                try {
                    ValidationUtility.validateLastName(dto.getLastName());
                } catch (BadRequestException ex) {
                    invalidInputs.add(ex.getMessage());
                }
            }
            if (dto.getRoles() != null && !dto.getRoles().isEmpty()) {
                dto.setRoles(dto.getRoles().stream().filter(r -> r != null && !r.isBlank()).collect(Collectors.toSet()));
                if (!dto.getRoles().isEmpty()) roles.addAll(dto.getRoles());
            }
        });
        return new UserUpdationResultDto(invalidInputs, usernames, emails, duplicateUsernamesInDtos, duplicateEmailsInDtos, roles, oldUsernames, duplicateOldUsernames, invalidOldUsernames);
    }

    private Map<String, Object> errorsStuffingIfAnyInUserUpdation(UserUpdationResultDto userUpdationResult,
                                                                  UserDetailsImpl user,
                                                                  String userHighestTopRole) {
        var mapOfErrors = new HashMap<String, Object>();
        if (!userUpdationResult.getInvalidInputs().isEmpty())
            mapOfErrors.put("invalid_inputs", userUpdationResult.getInvalidInputs());
        if (!userUpdationResult.getDuplicateUsernamesInDtos().isEmpty())
            mapOfErrors.put("duplicate_usernames_in_request", userUpdationResult.getDuplicateUsernamesInDtos());
        if (!userUpdationResult.getDuplicateEmailsInDtos().isEmpty())
            mapOfErrors.put("duplicate_emails_in_request", userUpdationResult.getDuplicateEmailsInDtos());
        if (!userUpdationResult.getInvalidOldUsernames().isEmpty())
            mapOfErrors.put("invalid_old_usernames", userUpdationResult.getInvalidOldUsernames());
        if (!userUpdationResult.getDuplicateOldUsernames().isEmpty())
            mapOfErrors.put("duplicate_old_usernames_in_request", userUpdationResult.getDuplicateOldUsernames());
        var notAllowedToAssignRoles = validateRolesRestriction(userUpdationResult.getRoles(), userHighestTopRole);
        if (!notAllowedToAssignRoles.isEmpty())
            mapOfErrors.put("not_allowed_to_assign_roles", notAllowedToAssignRoles);
        var ownUserInInputs = new HashSet<String>();
        if (userUpdationResult.getUsernames().contains(user.getUsername())) ownUserInInputs.add(user.getUsername());
        if (userUpdationResult.getEmails().contains(user.getUserModel().getEmail()))
            ownUserInInputs.add(user.getUserModel().getEmail());
        if (!ownUserInInputs.isEmpty())
            mapOfErrors.put("you_cannot_update_your_own_account_using_this_endpoint", ownUserInInputs);
        return mapOfErrors;
    }

    private ConflictingUsernamesEmailsResultDto getConflictingUsernamesEmails(UserUpdationResultDto userUpdationResult,
                                                                              Set<UserUpdationDto> dtos) {
        var usersFoundByUsernames = userRepo.findByUsernameIn(userUpdationResult.getUsernames());
        var usersFoundByEmails = userRepo.findByEmailIn(userUpdationResult.getEmails());
        var dtosUsernameToOldUsernameMap = new HashMap<String, String>();
        var dtosEmailToOldUsernameMap = new HashMap<String, String>();
        for (var dto : dtos) {
            if (dto.getUsername() != null)
                dtosUsernameToOldUsernameMap.put(dto.getUsername(), dto.getOldUsername());
            if (dto.getEmail() != null) dtosEmailToOldUsernameMap.put(dto.getEmail(), dto.getOldUsername());
        }
        var conflictingUsernames = usersFoundByUsernames.stream().filter(u -> {
            var requesterForUsername = dtosUsernameToOldUsernameMap.get(u.getUsername());
            return requesterForUsername != null && !u.getUsername().equals(requesterForUsername);
        }).map(UserModel::getUsername).collect(Collectors.toSet());
        var conflictingEmails = usersFoundByEmails.stream().filter(u -> {
            var requesterForEmail = dtosEmailToOldUsernameMap.get(u.getEmail());
            return requesterForEmail != null && !u.getUsername().equals(requesterForEmail);
        }).map(UserModel::getEmail).collect(Collectors.toSet());
        return new ConflictingUsernamesEmailsResultDto(conflictingUsernames, conflictingEmails);
    }

    private Map<String, Object> errorsStuffingIfAnyInUserUpdation(ConflictingUsernamesEmailsResultDto conflictingUsernamesEmailsResult) {
        var mapOfErrors = new HashMap<String, Object>();
        if (!conflictingUsernamesEmailsResult.getConflictingUsernames().isEmpty())
            mapOfErrors.put("conflicting_usernames", conflictingUsernamesEmailsResult.getConflictingUsernames());
        if (!conflictingUsernamesEmailsResult.getConflictingEmails().isEmpty())
            mapOfErrors.put("conflicting_emails", conflictingUsernamesEmailsResult.getConflictingEmails());
        return mapOfErrors;
    }

    private UserUpdationWithNewDetailsResultDto getResultOfUserUpdationWithNewDetails(UserUpdationResultDto userUpdationResult,
                                                                                      Set<UserUpdationDto> dtos,
                                                                                      UserDetailsImpl user,
                                                                                      String userHighestTopRole) {
        var resolvedRolesResult = resolveRoles(userUpdationResult.getRoles());
        var roleToRolenameMap = resolvedRolesResult.getRoles().stream().collect(Collectors.toMap(RoleModel::getRoleName, Function.identity()));
        var userToUsernameMap = userRepo.findByUsernameIn(userUpdationResult.getOldUsernames()).stream().collect(Collectors.toMap(UserModel::getUsername, Function.identity()));
        var updatedUsers = new HashSet<UserModel>();
        var usersToWhichWeHaveToRevokeTokens = new HashSet<UserModel>();
        var notFoundUsers = new HashSet<String>();
        var rolesOfUsers = new HashSet<String>();
        dtos.forEach(dto -> {
            var userToUpdate = userToUsernameMap.get(dto.getOldUsername());
            if (Objects.isNull(userToUpdate)) {
                notFoundUsers.add(dto.getOldUsername());
                return;
            }
            var isUpdated = false;
            var shouldRemoveTokens = false;
            if (dto.getUsername() != null && !dto.getUsername().equals(userToUpdate.getUsername())) {
                userToUpdate.setUsername(dto.getUsername());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.getEmail() != null && !dto.getEmail().equals(userToUpdate.getEmail())) {
                userToUpdate.setEmail(dto.getEmail());
                userToUpdate.setRealEmail(dto.getEmail());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.getPassword() != null) {
                userToUpdate.changePassword(passwordEncoder.encode(dto.getPassword()));
                isUpdated = true;
            }
            if (!userToUpdate.getRoles().isEmpty())
                userToUpdate.getRoles().forEach(role -> rolesOfUsers.add(role.getRoleName()));
            if (dto.getRoles() != null) {
                var rolesToAssign = dto.getRoles().stream().map(roleToRolenameMap::get).filter(Objects::nonNull).collect(Collectors.toSet());
                if (!userToUpdate.getRoles().equals(rolesToAssign)) {
                    userToUpdate.setRoles(rolesToAssign);
                    isUpdated = true;
                    shouldRemoveTokens = true;
                }
            }
            if (dto.getFirstName() != null && !dto.getFirstName().equals(userToUpdate.getFirstName())) {
                userToUpdate.setFirstName(dto.getFirstName());
                isUpdated = true;
            }
            if (dto.getMiddleName() != null && !dto.getMiddleName().equals(userToUpdate.getMiddleName())) {
                userToUpdate.setMiddleName(dto.getMiddleName());
                isUpdated = true;
            }
            if (dto.getLastName() != null && !dto.getLastName().equals(userToUpdate.getLastName())) {
                userToUpdate.setLastName(dto.getLastName());
                isUpdated = true;
            }
            if (dto.isEmailVerified() != userToUpdate.isEmailVerified()) {
                userToUpdate.setEmailVerified(dto.isEmailVerified());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountEnabled() != userToUpdate.isAccountEnabled()) {
                userToUpdate.setAccountEnabled(dto.isAccountEnabled());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountLocked() != userToUpdate.isAccountLocked()) {
                userToUpdate.recordLockedStatus(dto.isAccountLocked());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (dto.isAccountDeleted() != userToUpdate.isAccountDeleted()) {
                userToUpdate.recordAccountDeletion(true, user.getUsername());
                isUpdated = true;
                shouldRemoveTokens = true;
            }
            if (isUpdated) {
                userToUpdate.setUpdatedBy(user.getUsername());
                if (shouldRemoveTokens) usersToWhichWeHaveToRevokeTokens.add(userToUpdate);
                else updatedUsers.add(userToUpdate);
            }
        });
        var mapOfErrors = new HashMap<String, Object>();
        if (!notFoundUsers.isEmpty()) mapOfErrors.put("users_not_found", notFoundUsers);
        if (!rolesOfUsers.isEmpty()) {
            var notAllowedToAssignRoles = validateRolesRestriction(rolesOfUsers, userHighestTopRole);
            if (!notAllowedToAssignRoles.isEmpty())
                mapOfErrors.put("not_allowed_to_assign_roles", notAllowedToAssignRoles);
        }
        return new UserUpdationWithNewDetailsResultDto(mapOfErrors, updatedUsers, usersToWhichWeHaveToRevokeTokens);
    }
}
