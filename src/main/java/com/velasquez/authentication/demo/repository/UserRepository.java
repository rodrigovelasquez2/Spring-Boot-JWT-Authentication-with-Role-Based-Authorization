package com.velasquez.authentication.demo.repository;

import com.velasquez.authentication.demo.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<Users,Integer> {
        Optional<Users> findByEmail(String email);
}
