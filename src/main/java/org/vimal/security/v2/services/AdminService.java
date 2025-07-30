package org.vimal.security.v2.services;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.vimal.security.v2.dtos.ResolvedRolesResultDto;
import org.vimal.security.v2.dtos.UserCreationUpdationDto;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;

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
}
