package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserCreationResultDto {
    public Set<String> invalidInputs;
    public Set<String> usernames;
    public Set<String> emails;
    public Set<String> duplicateUsernamesInDtos;
    public Set<String> duplicateEmailsInDtos;
    public Set<String> roles;
}
