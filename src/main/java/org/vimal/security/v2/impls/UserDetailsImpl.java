package org.vimal.security.v2.impls;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.vimal.security.v2.models.UserModel;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class UserDetailsImpl implements UserDetails {
    @Getter
    private final UserModel userModel;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(UserModel userModel) {
        this.userModel = userModel;
        this.authorities = computeAuthorities(userModel);
    }

    public UserDetailsImpl(UserModel userModel,
                           Collection<? extends GrantedAuthority> authorities) {
        this.userModel = userModel;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    private Collection<? extends GrantedAuthority> computeAuthorities(UserModel user) {
        return user.getRoles().stream()
                .flatMap(role -> Stream.concat(
                        Stream.of(new SimpleGrantedAuthority(role.getRoleName())),
                        role.getPermissions().stream().map(permission -> new SimpleGrantedAuthority(permission.getPermissionName()))
                ))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() {
        return userModel.getPassword();
    }

    @Override
    public String getUsername() {
        return userModel.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return userModel.getCreatedAt().plus(36500, ChronoUnit.DAYS).isAfter(Instant.now());
    }

    @Override
    public boolean isAccountNonLocked() {
        return !userModel.isAccountLocked() || userModel.getLastLockedAt().plus(1, ChronoUnit.DAYS).isBefore(Instant.now());
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return userModel.getPasswordChangedAt().plus(365, ChronoUnit.DAYS).isAfter(Instant.now());
    }

    @Override
    public boolean isEnabled() {
        return userModel.isAccountEnabled();
    }
}
