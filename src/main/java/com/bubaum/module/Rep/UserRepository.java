package com.bubaum.module.Rep;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.bubaum.module.Model.Users;

public interface UserRepository extends JpaRepository<Users,Long> {
    
    Optional<Users> findById(String userId);
}
