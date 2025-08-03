package org.vimal.security.v2.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.vimal.security.v2.enums.FeatureFlags;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "users",
        indexes = {
                @Index(name = "idx_username", columnList = "username", unique = true),
                @Index(name = "idx_email", columnList = "email", unique = true),
                @Index(name = "idx_real_email", columnList = "realEmail", unique = true)
        },
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_users_username", columnNames = "username"),
                @UniqueConstraint(name = "uk_users_email", columnNames = "email"),
                @UniqueConstraint(name = "uk_users_real_email", columnNames = "realEmail")
        })
@Cache(usage = CacheConcurrencyStrategy.READ_WRITE)
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class UserModel {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(columnDefinition = "UUID", updatable = false, nullable = false, unique = true)
    private UUID id;

    @Column(name = "first_name", nullable = false, length = 50)
    private String firstName;

    @Column(name = "middle_name", length = 50)
    private String middleName;

    @Column(name = "last_name", length = 50)
    private String lastName;

    @Column(name = "username", nullable = false, unique = true, length = 100)
    private String username;

    @JsonIgnore
    @Column(name = "password", nullable = false, length = 512)
    private String password;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @JsonIgnore
    @Column(name = "real_email", nullable = false, unique = true)
    private String realEmail;

    @Builder.Default
    @Column(name = "email_verified", nullable = false)
    private boolean emailVerified = false;

    @Builder.Default
    @Column(name = "mfa_enabled", nullable = false)
    private boolean mfaEnabled = false;

    @Builder.Default
    @Column(name = "account_locked", nullable = false)
    private boolean accountLocked = false;

    @JsonIgnore
    @Builder.Default
    @Column(name = "account_deleted", nullable = false)
    private boolean accountDeleted = false;

    @JsonIgnore
    @Column(name = "last_account_deleted_at")
    private Instant lastAccountDeletedAt;

    @JsonIgnore
    @Column(name = "last_deleted_undeleted_by", length = 100)
    private String lastDeletedUndeletedBy;

    public void recordAccountDeletion(boolean deleted,
                                      String deletedUndeletedBy) {
        this.accountDeleted = deleted;
        if (deleted) this.lastAccountDeletedAt = Instant.now();
        this.lastDeletedUndeletedBy = deletedUndeletedBy;
    }

    @Builder.Default
    @Column(name = "account_enabled", nullable = false)
    private boolean accountEnabled = true;

    @Builder.Default
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Builder.Default
    @Column(name = "failed_mfa_attempts", nullable = false)
    private int failedMfaAttempts = 0;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    @Column(name = "password_changed_at", nullable = false)
    private Instant passwordChangedAt;

    @ManyToMany(fetch = FetchType.EAGER, cascade = {CascadeType.PERSIST, CascadeType.MERGE})
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_name", referencedColumnName = "role_name"))
    private Set<RoleModel> roles;

    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @JsonIgnore
    @Column(name = "auth_app_secret", length = 512)
    private String authAppSecret;

    @Column(name = "last_locked_at")
    private Instant lastLockedAt;

    @Column(name = "created_by", nullable = false, updatable = false, length = 100)
    private String createdBy;

    @Column(name = "updated_by", nullable = false, length = 100)
    private String updatedBy;

    @PrePersist
    protected void onCreate() {
        var now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (Objects.isNull(this.passwordChangedAt)) {
            this.passwordChangedAt = now;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public void recordSuccessfulLogin() {
        this.lastLoginAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
        if (this.accountLocked) {
            this.accountLocked = false;
        }
    }

    public void recordFailedLoginAttempt() {
        this.failedLoginAttempts++;
        if (this.failedLoginAttempts >= MAX_FAILED_ATTEMPTS) {
            this.accountLocked = true;
            this.lastLockedAt = Instant.now();
        }
        if (this.failedLoginAttempts >= UPPER_MAX_FAILED_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    public void recordFailedMfaAttempt() {
        this.failedMfaAttempts++;
        if (this.failedMfaAttempts >= MAX_FAILED_MFA_ATTEMPTS) {
            this.accountLocked = true;
            this.lastLockedAt = Instant.now();
        }
        if (this.failedMfaAttempts >= UPPER_MAX_FAILED_MFA_ATTEMPTS) {
            this.accountEnabled = false;
        }
    }

    public void recordSuccessfulMfaAttempt() {
        recordSuccessfulLogin();
        this.failedMfaAttempts = 0;
    }

    public void changePassword(String newPassword) {
        this.password = newPassword;
        this.passwordChangedAt = Instant.now();
        this.failedLoginAttempts = 0;
        this.failedMfaAttempts = 0;
    }

    public void recordLockedStatus(boolean locked) {
        this.accountLocked = locked;
        this.lastLockedAt = locked ? Instant.now() : null;
        if (!locked) {
            this.failedLoginAttempts = 0;
            this.failedMfaAttempts = 0;
        }
    }

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int UPPER_MAX_FAILED_ATTEMPTS = 10;
    private static final int MAX_FAILED_MFA_ATTEMPTS = 3;
    private static final int UPPER_MAX_FAILED_MFA_ATTEMPTS = 5;

    @Getter
    public enum MfaType {
        EMAIL,
        AUTHENTICATOR_APP;

        public FeatureFlags getFeatureFlag() {
            return switch (this) {
                case EMAIL -> FeatureFlags.MFA_EMAIL;
                case AUTHENTICATOR_APP -> FeatureFlags.MFA_AUTHENTICATOR_APP;
            };
        }
    }

    @ElementCollection(targetClass = MfaType.class, fetch = FetchType.EAGER)
    @CollectionTable(name = "user_mfa_methods",
            joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "mfa_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<MfaType> enabledMfaMethods;

    public void enableMfaMethod(MfaType mfaType) {
        this.enabledMfaMethods.add(mfaType);
        this.mfaEnabled = true;
    }

    public void disableMfaMethod(MfaType mfaType) {
        this.enabledMfaMethods.remove(mfaType);
        this.mfaEnabled = !this.enabledMfaMethods.isEmpty();
    }

    public boolean hasMfaEnabled(MfaType mfaType) {
        return this.enabledMfaMethods.contains(mfaType);
    }
}
