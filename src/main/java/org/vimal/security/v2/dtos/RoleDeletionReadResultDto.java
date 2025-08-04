package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v2.models.RoleModel;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RoleDeletionReadResultDto {
    private Set<String> invalidInputs;
    private Collection<RoleModel> roles;
    private Set<String> notFoundRoles;
    private long usersCountThatHaveSomeOfTheseRoles;
    private Set<UUID> userIdsThatHaveSomeOfTheseRoles;
}
