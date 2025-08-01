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
public class ConflictingUsernamesEmailsResultDto {
    private Collection<String> conflictingUsernames;
    private Collection<String> conflictingEmails;
}
