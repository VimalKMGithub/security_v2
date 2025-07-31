package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
public class UserCreationDto extends RegistrationDto {
    public Collection<String> roles;
    public boolean emailVerified;
    public boolean accountLocked;
    public boolean accountEnabled;
    public boolean accountDeleted;
}
