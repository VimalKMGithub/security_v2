package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.ResolvedRolesResultDto;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AdminService {
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    public ResponseEntity<Map<String, Object>> createUser(UserCreationUpdationDto dto) {
        return createUsers(Set.of(dto));
    }

    public ResponseEntity<Map<String, Object>> createUsers(Collection<UserCreationUpdationDto> dtos) {
        var invalidInputs = new HashSet<String>();
        var roles = new HashSet<String>();
        var duplicateUsernamesInDtos = new HashSet<String>();
        var duplicateEmailsInDtos = new HashSet<String>();
        var usernames = new HashSet<String>();
        var emails = new HashSet<String>();
    }

    public Collection<String> validateRolesAssignment(Collection<String> roles, String currentUserHighestTopRole) {
        var notAllowedToAssignRoles = new HashSet<String>();
        if (SystemRoles.TOP_ROLES.getFirst().equals(currentUserHighestTopRole) || Objects.isNull(roles) || roles.isEmpty())
            return notAllowedToAssignRoles;
        for (var role : roles) {
            if (SystemRoles.TOP_ROLES.contains(role))
                if (Objects.isNull(currentUserHighestTopRole) || SystemRoles.TOP_ROLES.indexOf(role) <= SystemRoles.TOP_ROLES.indexOf(currentUserHighestTopRole))
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
