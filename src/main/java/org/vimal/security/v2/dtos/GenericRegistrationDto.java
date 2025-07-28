package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenericRegistrationDto {
    public String username;
    public String password;
    public String email;
    public String firstName;
    public String middleName;
    public String lastName;
}
