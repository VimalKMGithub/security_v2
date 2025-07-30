package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPwdUsingOldPwdDto extends ResetPwdDto {
    private String oldPassword;
}
