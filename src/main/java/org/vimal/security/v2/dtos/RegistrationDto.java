package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistrationDto {
    private String username;
    private String password;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
}
