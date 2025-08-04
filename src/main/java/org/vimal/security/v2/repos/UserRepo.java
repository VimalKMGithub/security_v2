package org.vimal.security.v2.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v2.models.UserModel;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface UserRepo extends JpaRepository<UserModel, UUID> {
    Optional<UserModel> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByRealEmail(String realEmail);

    Optional<UserModel> findByEmail(String storedEmail);

    Set<UserModel> findByUsernameIn(Set<String> usernames);

    Set<UserModel> findByEmailIn(Set<String> emails);
}
