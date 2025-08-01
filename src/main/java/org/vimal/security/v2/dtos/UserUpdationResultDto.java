package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
public class UserUpdationResultDto extends UserCreationResultDto {
    private Set<String> oldUsernames;
    private Set<String> duplicateOldUsernames;
    private Set<String> invalidOldUsernames;

    public UserUpdationResultDto(Set<String> invalidInputs,
                                 Set<String> usernames,
                                 Set<String> emails,
                                 Set<String> duplicateUsernamesInDtos,
                                 Set<String> duplicateEmailsInDtos,
                                 Set<String> roles,
                                 Set<String> oldUsernames,
                                 Set<String> duplicateOldUsernames,
                                 Set<String> invalidOldUsernames) {
        super(invalidInputs, usernames, emails, duplicateUsernamesInDtos, duplicateEmailsInDtos, roles);
        this.oldUsernames = oldUsernames;
        this.duplicateOldUsernames = duplicateOldUsernames;
        this.invalidOldUsernames = invalidOldUsernames;
    }
}
