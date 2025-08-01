package org.vimal.security.v2.impls;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.vimal.security.v2.configs.PropertiesConfig;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.models.PermissionModel;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.PermissionRepo;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class CommandLineRunnerImpl implements CommandLineRunner {
    private final PropertiesConfig propertiesConfig;
    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final PermissionRepo permissionRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void run(String... args) {
        log.info("Initializing system permissions, roles, and default users...");
        initializeSystemPermissionsIfAbsent();
        initializeSystemRolesIfAbsent();
        assignPermissionsToRoles();
        initializeDefaultUsersIfAbsent();
        log.info("System permissions, roles, and default users initialized successfully.");
    }

    private void initializeSystemPermissionsIfAbsent() {
        var permissionNames = Arrays.stream(SystemPermissions.values()).map(SystemPermissions::name).collect(Collectors.toSet());
        var existingPermissions = permissionRepo.findAllById(permissionNames).stream().map(PermissionModel::getPermissionName).collect(Collectors.toSet());
        var missingPermissions = permissionNames.stream().filter(name -> !existingPermissions.contains(name)).collect(Collectors.toSet());
        var permissionsToCreate = missingPermissions.stream().map(name -> PermissionModel.builder().permissionName(name).systemPermission(true).createdBy("SYSTEM").updatedBy("SYSTEM").build()).collect(Collectors.toSet());
        if (!permissionsToCreate.isEmpty()) permissionRepo.saveAll(permissionsToCreate);
    }

    private void initializeSystemRolesIfAbsent() {
        var roleNames = Arrays.stream(SystemRoles.values()).map(SystemRoles::name).collect(Collectors.toSet());
        var existingRoles = roleRepo.findAllById(roleNames).stream().map(RoleModel::getRoleName).collect(Collectors.toSet());
        var missingRoles = roleNames.stream().filter(name -> !existingRoles.contains(name)).collect(Collectors.toSet());
        var rolesToCreate = missingRoles.stream().map(name -> RoleModel.builder().roleName(name).systemRole(true).createdBy("SYSTEM").updatedBy("SYSTEM").build()).collect(Collectors.toSet());
        if (!rolesToCreate.isEmpty()) roleRepo.saveAll(rolesToCreate);
    }

    private void assignPermissionsToRoles() {
        assignPermissionsToRole(SystemRoles.ROLE_MANAGE_ROLES.name(), Set.of(SystemPermissions.CAN_CREATE_ROLE.name(), SystemPermissions.CAN_READ_ROLE.name(), SystemPermissions.CAN_UPDATE_ROLE.name(), SystemPermissions.CAN_DELETE_ROLE.name()));
        assignPermissionsToRole(SystemRoles.ROLE_MANAGE_USERS.name(), Set.of(SystemPermissions.CAN_CREATE_USER.name(), SystemPermissions.CAN_READ_USER.name(), SystemPermissions.CAN_UPDATE_USER.name(), SystemPermissions.CAN_DELETE_USER.name()));
        assignPermissionsToRole(SystemRoles.ROLE_MANAGE_PERMISSIONS.name(), Set.of(SystemPermissions.CAN_READ_PERMISSION.name()));
    }

    private void assignPermissionsToRole(String role,
                                         Set<String> permissions) {
        var roleModel = roleRepo.findById(role).orElseThrow(() -> new RuntimeException("Role not found: " + role));
        var permissionModels = permissionRepo.findAllById(permissions);
        if (!permissionModels.isEmpty()) {
            roleModel.setPermissions(new HashSet<>(permissionModels));
            roleModel.setUpdatedBy("SYSTEM");
            roleRepo.save(roleModel);
        }
    }

    private void initializeDefaultUsersIfAbsent() {
        createUserIfNotExists(propertiesConfig.getGodUserEmail(), propertiesConfig.getGodUserUsername(), "God", propertiesConfig.getGodUserPassword(), Set.of(SystemRoles.ROLE_GOD.name()));
        createUserIfNotExists(propertiesConfig.getGlobalAdminUserEmail(), propertiesConfig.getGlobalAdminUserUsername(), "Global Admin", propertiesConfig.getGlobalAdminUserPassword(), Set.of(SystemRoles.ROLE_GLOBAL_ADMIN.name()));
    }

    private void createUserIfNotExists(String email,
                                       String username,
                                       String firstName,
                                       String password,
                                       Set<String> roleNames) {
        if (!userRepo.existsByUsername(username)) {
            var user = UserModel.builder()
                    .email(email)
                    .realEmail(email)
                    .username(username)
                    .firstName(firstName)
                    .password(passwordEncoder.encode(password))
                    .roles(new HashSet<>(roleRepo.findAllById(roleNames)))
                    .emailVerified(true)
                    .createdBy("SYSTEM")
                    .updatedBy("SYSTEM")
                    .build();
            userRepo.save(user);
        }
    }
}
