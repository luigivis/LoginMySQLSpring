package com.example.loginmysqlauth.repository;

import com.example.loginmysqlauth.entity.Role;
import com.example.loginmysqlauth.enums.ERole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);
}
