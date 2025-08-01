package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserCreationResultDto {
    public Collection<String> invalidInputs;
    public Collection<String> usernames;
    public Collection<String> emails;
    public Collection<String> duplicateUsernamesInDtos;
    public Collection<String> duplicateEmailsInDtos;
    public Collection<String> roles;
}
