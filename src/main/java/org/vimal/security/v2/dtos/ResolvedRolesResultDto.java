package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v2.models.RoleModel;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResolvedRolesResultDto {
    private Collection<RoleModel> roles;
    private Collection<String> missingRoles;
}
