package org.vimal.security.v2.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import org.vimal.security.v2.models.PermissionModel;

@Repository
public interface PermissionRepo extends JpaRepository<PermissionModel, String> {
}
