package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdDto {
    private String username;
    private String email;
    private String usernameOrEmail;
    private String otp;
    public String password;
    public String confirmPassword;
}
