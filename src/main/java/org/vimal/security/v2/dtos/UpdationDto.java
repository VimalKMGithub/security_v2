package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdationDto extends ResetPwdUsingOldPwdDto {
    private String username;
    private String email;
    private String firstName;
    private String middleName;
    private String lastName;
}
