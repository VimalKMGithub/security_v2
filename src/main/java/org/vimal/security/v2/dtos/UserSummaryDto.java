package org.vimal.security.v2.dtos;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.Collection;
import java.util.UUID;

@Getter
@Setter
public class UserSummaryDto {
    private UUID id;
    private String firstName;
    private String middleName;
    private String lastName;
    private String username;
    private String email;
    private String createdBy;
    private String updatedBy;
    private Collection<String> roles;
    private Collection<String> mfaMethods;
    private Instant lastLoginAt;
    private Instant passwordChangedAt;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant lastLockedAt;
    private boolean emailVerified;
    private boolean mfaEnabled;
    private boolean accountLocked;
    private boolean accountEnabled;
    private int failedLoginAttempts;
    private int failedMfaAttempts;
}
