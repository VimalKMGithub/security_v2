package org.vimal.security.v2.impls;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.vimal.security.v2.exceptions.CustomLockedException;
import org.vimal.security.v2.exceptions.MailNotVerifiedException;
import org.vimal.security.v2.models.UserModel;
import org.vimal.security.v2.repos.UserRepo;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Component
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        var user = userRepo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));
        checkAccountStatus(user);
        return new UserDetailsImpl(user);
    }

    private void checkAccountStatus(UserModel user) {
        if (user.isAccountDeleted()) {
            throw new UsernameNotFoundException("Invalid credentials");
        }
        if (!user.isEmailVerified()) {
            throw new MailNotVerifiedException("Please verify your email first");
        }
        if (user.isAccountLocked() && user.getLastLockedAt().plus(1, ChronoUnit.DAYS).isAfter(Instant.now())) {
            throw new CustomLockedException("Account is temporarily locked. Please try again later.");
        }
    }
}
