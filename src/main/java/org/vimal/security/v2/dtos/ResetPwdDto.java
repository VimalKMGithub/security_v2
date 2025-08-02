package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdDto {
    private String usernameOrEmail;
    private String method;
    private String otpTotp;
    public String password;
    public String confirmPassword;
}
