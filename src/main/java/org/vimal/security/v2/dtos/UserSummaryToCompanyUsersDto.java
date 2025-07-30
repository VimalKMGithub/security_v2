package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public class UserSummaryToCompanyUsersDto extends UserSummaryDto {
    private boolean accountDeleted;
    private Instant accountDeletedAt;
    private String deletedBy;
}
