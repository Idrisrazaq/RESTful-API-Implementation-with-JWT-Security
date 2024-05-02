package com.example.jwt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Integer>{
	
	Optional<User> findByUserEmail(String email);
	
}
