package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
public class UserCreationDto extends RegistrationDto {
    private Collection<String> roles;
    private boolean emailVerified;
    private boolean accountLocked;
    private boolean accountEnabled;
    private boolean accountDeleted;
}
