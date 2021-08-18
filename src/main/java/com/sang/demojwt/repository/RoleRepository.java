package com.sang.demojwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sang.demojwt.model.ERole;
import com.sang.demojwt.model.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{
	Optional<Role> findByName(ERole name);
}
