package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenericResetPwdDto {
    public String username;
    public String email;
    public String usernameOrEmail;
    public String otp;
    public String password;
    public String confirmPassword;
}
