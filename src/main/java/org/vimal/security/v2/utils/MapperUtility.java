package org.vimal.security.v2.utils;

import org.vimal.security.v2.dtos.UserSummaryDto;
import org.vimal.security.v2.dtos.UserSummaryToCompanyUsersDto;
import org.vimal.security.v2.models.RoleModel;
import org.vimal.security.v2.models.UserModel;

import java.util.stream.Collectors;

public class MapperUtility {
    public static UserSummaryDto toUserSummaryDto(UserModel user) {
        var dto = new UserSummaryDto();
        mapCommonFields(user, dto);
        return dto;
    }

    public static UserSummaryToCompanyUsersDto toUserSummaryToCompanyUsersDto(UserModel user) {
        var dto = new UserSummaryToCompanyUsersDto();
        mapCommonFields(user, dto);
        dto.setAccountDeleted(user.isAccountDeleted());
        dto.setAccountDeletedAt(user.getAccountDeletedAt());
        dto.setDeletedBy(user.getDeletedBy());
        return dto;
    }

    public static void mapCommonFields(UserModel user,
                                       UserSummaryDto dto) {
        dto.setId(user.getId());
        dto.setFirstName(user.getFirstName());
        dto.setMiddleName(user.getMiddleName());
        dto.setLastName(user.getLastName());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setCreatedBy(user.getCreatedBy());
        dto.setUpdatedBy(user.getUpdatedBy());
        dto.setRoles(user.getRoles().stream().map(RoleModel::getRoleName).collect(Collectors.toSet()));
        dto.setMfaMethods(user.getEnabledMfaMethods() != null ? user.getEnabledMfaMethods().stream().map(UserModel.MfaType::name).collect(Collectors.toSet()) : null);
        dto.setLastLoginAt(user.getLastLoginAt());
        dto.setPasswordChangedAt(user.getPasswordChangedAt());
        dto.setCreatedAt(user.getCreatedAt());
        dto.setUpdatedAt(user.getUpdatedAt());
        dto.setLastLockedAt(user.getLastLockedAt());
        dto.setEmailVerified(user.isEmailVerified());
        dto.setMfaEnabled(user.isMfaEnabled());
        dto.setAccountLocked(user.isAccountLocked());
        dto.setAccountEnabled(user.isAccountEnabled());
        dto.setFailedLoginAttempts(user.getFailedLoginAttempts());
        dto.setFailedMfaAttempts(user.getFailedMfaAttempts());
    }
}
