package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v2.models.UserModel;

import java.util.Collection;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserUpdationWithNewDetailsResultDto {
    private Map<String, Object> mapOfErrors;
    private Collection<UserModel> updatedUsers;
    private Collection<UserModel> usersToWhichWeHaveToRevokeTokens;
    private Collection<String> notFoundUsers;
    private Collection<String> rolesOfUsersToUpdate;
}
