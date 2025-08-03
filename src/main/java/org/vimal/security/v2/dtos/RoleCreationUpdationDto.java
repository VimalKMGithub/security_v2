package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
public class RoleCreationUpdationDto {
    private String roleName;
    private String description;
    private Set<String> permissions;
}
