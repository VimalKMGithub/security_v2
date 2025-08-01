package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Collection;

@Getter
@Setter
@NoArgsConstructor
public class UserUpdationResultDto extends UserCreationResultDto {
    private Collection<String> oldUsernames;
    private Collection<String> duplicateOldUsernames;
    private Collection<String> invalidOldUsernames;

    public UserUpdationResultDto(Collection<String> invalidInputs,
                                 Collection<String> usernames,
                                 Collection<String> emails,
                                 Collection<String> duplicateUsernamesInDtos,
                                 Collection<String> duplicateEmailsInDtos,
                                 Collection<String> roles,
                                 Collection<String> oldUsernames,
                                 Collection<String> duplicateOldUsernames,
                                 Collection<String> invalidOldUsernames) {
        super(invalidInputs, usernames, emails, duplicateUsernamesInDtos, duplicateEmailsInDtos, roles);
        this.oldUsernames = oldUsernames;
        this.duplicateOldUsernames = duplicateOldUsernames;
        this.invalidOldUsernames = invalidOldUsernames;
    }
}
