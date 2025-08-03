package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v2.models.PermissionModel;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResolvedPermissionsResultDto {
    private Map<String, PermissionModel> resolvedPermissionsMap;
    private Set<String> missingPermissions;
}
