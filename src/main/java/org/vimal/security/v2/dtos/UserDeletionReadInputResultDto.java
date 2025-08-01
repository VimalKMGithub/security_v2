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
public class UserDeletionReadInputResultDto {
    private Set<String> invalidInputs;
    private Set<String> usernames;
    private Set<String> emails;
    private Set<String> ownUserInInputs;
}
