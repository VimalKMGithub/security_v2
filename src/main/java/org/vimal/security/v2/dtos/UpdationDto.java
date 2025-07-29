package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdationDto {
    private String username;
    private String firstName;
    private String middleName;
    private String lastName;
    private String oldPassword;
}
