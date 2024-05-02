package com.example.jwt.repository;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.model.AccessToken;

public interface AccessTokenRepository extends JpaRepository<AccessToken, Integer>{

	boolean existsByTokenAndIsBlocked(String at, boolean b);

	List<AccessToken> findAllByExpirationLessThan(LocalDateTime date);

	AccessToken findByToken(String accessToken);

}
