package org.vimal.security.v2.enums;

import java.util.List;

public enum SystemRoles {
    ROLE_GOD,
    ROLE_GLOBAL_ADMIN,
    ROLE_SUPER_ADMIN,
    ROLE_ADMIN,
    ROLE_MANAGE_ROLES,
    ROLE_MANAGE_USERS,
    ROLE_MANAGE_PERMISSIONS;

    public static final List<String> TOP_ROLES = List.of(
            ROLE_GOD.name(),
            ROLE_GLOBAL_ADMIN.name(),
            ROLE_SUPER_ADMIN.name(),
            ROLE_ADMIN.name()
    );
}
