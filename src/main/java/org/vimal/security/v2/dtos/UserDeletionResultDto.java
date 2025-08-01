package org.vimal.security.v2.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.vimal.security.v2.models.UserModel;

import java.util.Map;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserDeletionResultDto {
    private Map<String, Object> mapOfErrors;
    private Set<UserModel> usersToDelete;
    private Set<UserModel> softDeletedUsers;
    private Set<String> rolesOfSoftDeletedUsers;
}
