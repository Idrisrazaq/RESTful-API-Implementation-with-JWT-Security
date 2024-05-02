package com.example.jwt.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.model.RefreshToken;
import com.example.jwt.model.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer>{

	boolean existsByTokenAndIsBlocked(String rt, boolean b);

	List<RefreshToken> findAllByExpirationLessThan(LocalDateTime now);

	RefreshToken findByToken(String refreshToken);

	User findUserByToken(String refreshToken);

}
