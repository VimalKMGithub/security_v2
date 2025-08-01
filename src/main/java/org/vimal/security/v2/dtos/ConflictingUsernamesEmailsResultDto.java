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
public class ConflictingUsernamesEmailsResultDto {
    private Set<String> conflictingUsernames;
    private Set<String> conflictingEmails;
}
