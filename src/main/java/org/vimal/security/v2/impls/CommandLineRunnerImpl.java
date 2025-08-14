package org.vimal.security.v2.impls;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.vimal.security.v2.configs.PropertiesConfig;
import org.vimal.security.v2.dtos.SystemUserDto;
import org.vimal.security.v2.enums.SystemPermissions;
import org.vimal.security.v2.enums.SystemRoles;
import org.vimal.security.v2.models.PermissionModel;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.PermissionRepo;
import org.vimal.security.v2.repos.RoleRepo;
import org.vimal.security.v2.repos.UserRepo;

import java.util.HashSet;
import java.util.Set;

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
        var permissionNames = new HashSet<String>();
        for (SystemPermissions permission : SystemPermissions.values()) {
            permissionNames.add(permission.name());
        }
        var existingPermissions = new HashSet<String>();
        for (PermissionModel p : permissionRepo.findAllById(permissionNames)) {
            existingPermissions.add(p.getPermissionName());
        }
        var permissionsToCreate = new HashSet<PermissionModel>();
        for (String name : permissionNames) {
            if (!existingPermissions.contains(name)) {
                permissionsToCreate.add(PermissionModel.builder()
                        .permissionName(name)
                        .systemPermission(true)
                        .createdBy("SYSTEM")
                        .updatedBy("SYSTEM")
                        .build());
            }
        }
        if (!permissionsToCreate.isEmpty()) {
            permissionRepo.saveAll(permissionsToCreate);
        }
    }

    private void initializeSystemRolesIfAbsent() {
        var roleNames = new HashSet<String>();
        for (SystemRoles role : SystemRoles.values()) {
            roleNames.add(role.name());
        }
        var existingRoles = new HashSet<String>();
        for (RoleModel r : roleRepo.findAllById(roleNames)) {
            existingRoles.add(r.getRoleName());
        }
        var rolesToCreate = new HashSet<RoleModel>();
        for (String name : roleNames) {
            if (!existingRoles.contains(name)) {
                rolesToCreate.add(RoleModel.builder()
                        .roleName(name)
                        .systemRole(true)
                        .createdBy("SYSTEM")
                        .updatedBy("SYSTEM")
                        .build());
            }
        }
        if (!rolesToCreate.isEmpty()) {
            roleRepo.saveAll(rolesToCreate);
        }
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
        var systemUsers = Set.of(new SystemUserDto(propertiesConfig.getGodUserUsername(), propertiesConfig.getGodUserPassword(), propertiesConfig.getGodUserEmail(), "God", Set.of(SystemRoles.ROLE_GOD.name())), new SystemUserDto(propertiesConfig.getGlobalAdminUserUsername(), propertiesConfig.getGlobalAdminUserPassword(), propertiesConfig.getGlobalAdminUserEmail(), "Global Admin", Set.of(SystemRoles.ROLE_GLOBAL_ADMIN.name())));
        var existingUsers = userRepo.findByUsernameIn(Set.of(propertiesConfig.getGodUserUsername(), propertiesConfig.getGlobalAdminUserUsername()));
        var existingUsersUsernames = new HashSet<String>();
        for (var user : existingUsers) {
            existingUsersUsernames.add(user.getUsername());
        }
        var newUsers = new HashSet<UserModel>();
        for (var user : systemUsers) {
            if (!existingUsersUsernames.contains(user.getUsername())) {
                newUsers.add(UserModel.builder()
                        .email(user.getEmail())
                        .realEmail(user.getEmail())
                        .username(user.getUsername())
                        .firstName(user.getFirstName())
                        .password(passwordEncoder.encode(user.getPassword()))
                        .roles(new HashSet<>(roleRepo.findAllById(user.getRoles())))
                        .emailVerified(true)
                        .createdBy("SYSTEM")
                        .updatedBy("SYSTEM")
                        .build());
            }
        }
        if (!newUsers.isEmpty()) {
            userRepo.saveAll(newUsers);
        }
    }
}
