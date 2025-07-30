package org.vimal.security.v2.services;

import io.getunleash.Unleash;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.ResolvedRolesResultDto;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.enums.FeatureFlags;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.exceptions.BadRequestException;
import org.vimal.security.v2.exceptions.ServiceUnavailableException;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;
import org.vimal.security.v2.utils.InputValidationUtility;
import org.vimal.security.v2.utils.MapperUtility;
import org.vimal.security.v2.utils.UserUtility;
import org.vimal.security.v2.utils.ValidationUtility;

import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {
    private static final int MAX_USERS_TO_CREATE_AT_A_TIME = 100;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;
    private final Unleash unleash;

    public ResponseEntity<Map<String, Object>> createUser(UserCreationUpdationDto dto) {
        return createUsers(Set.of(dto));
    }

    public ResponseEntity<Map<String, Object>> createUsers(Collection<UserCreationUpdationDto> dtos) {
        var creator = UserUtility.getCurrentAuthenticatedUserDetails();
        var creatorHighestTopRole = UserUtility.getUserHighestTopRole(creator);
        var isTopRole = SystemRoles.TOP_ROLES.getFirst().equals(creatorHighestTopRole);
        if (unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS.name()) || isTopRole) {
            if (!isTopRole && !unleash.isEnabled(FeatureFlags.ALLOW_CREATE_USERS_BY_USERS_HAVE_PERMISSION_TO_CREATE_USERS.name()))
                throw new ServiceUnavailableException("Creation of new users is currently disabled. Please try again later");
            if (dtos.isEmpty()) throw new BadRequestException("No users to create");
            if (dtos.size() > MAX_USERS_TO_CREATE_AT_A_TIME)
                throw new BadRequestException("Cannot create more than " + MAX_USERS_TO_CREATE_AT_A_TIME + " users at a time");
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
            var notAllowedToAssignRoles = validateRolesAssignment(roles, creatorHighestTopRole);
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

    public Collection<String> validateRolesAssignment(Collection<String> roles, String assignerTopRole) {
        var notAllowedToAssignRoles = new HashSet<String>();
        if (SystemRoles.TOP_ROLES.getFirst().equals(assignerTopRole) || Objects.isNull(roles) || roles.isEmpty())
            return notAllowedToAssignRoles;
        for (var role : roles) {
            if (SystemRoles.TOP_ROLES.contains(role))
                if (Objects.isNull(assignerTopRole) || SystemRoles.TOP_ROLES.indexOf(role) <= SystemRoles.TOP_ROLES.indexOf(assignerTopRole))
                    notAllowedToAssignRoles.add(role);
        }
        return notAllowedToAssignRoles;
    }

    public ResolvedRolesResultDto resolveRoles(Collection<String> roles) {
        if (Objects.isNull(roles) || roles.isEmpty())
            return new ResolvedRolesResultDto(new HashSet<>(), new HashSet<>());
        var foundRoles = roleRepo.findAllById(roles);
        var foundRoleNames = foundRoles.stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        return new ResolvedRolesResultDto(foundRoles, roles.stream().filter(role -> !foundRoleNames.contains(role)).collect(Collectors.toSet()));
    }

    public UserModel toUserModel(UserCreationUpdationDto dto,
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
                .deletedBy(creator.getUsername())
                .build();
    }
}
