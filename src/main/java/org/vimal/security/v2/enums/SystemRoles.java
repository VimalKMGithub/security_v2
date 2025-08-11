package org.vimal.security.v2.enums;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

    public static final Map<String, Integer> ROLE_PRIORITY_MAP = buildRolePriorityMap();

    private static Map<String, Integer> buildRolePriorityMap() {
        var map = new HashMap<String, Integer>();
        for (int i = 0; i < SystemRoles.TOP_ROLES.size(); i++) {
            map.put(SystemRoles.TOP_ROLES.get(i), i);
        }
        return Collections.unmodifiableMap(map);
    }
}
