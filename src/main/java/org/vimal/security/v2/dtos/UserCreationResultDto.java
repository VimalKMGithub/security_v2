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
    private Collection<String> invalidInputs;
    private Collection<String> usernames;
    private Collection<String> emails;
    private Collection<String> duplicateUsernamesInDtos;
    private Collection<String> duplicateEmailsInDtos;
    private Collection<String> roles;
}
