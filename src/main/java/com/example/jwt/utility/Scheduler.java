package com.example.jwt.utility;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.example.jwt.model.AccessToken;
import com.example.jwt.model.RefreshToken;
import com.example.jwt.repository.AccessTokenRepository;
import com.example.jwt.repository.RefreshTokenRepository;

import lombok.AllArgsConstructor;

@EnableScheduling
@Component
@AllArgsConstructor
public class Scheduler {
	
	private AccessTokenRepository accessTokenRepository;
	private RefreshTokenRepository refreshTokenRepository;
	
//	@Scheduled(fixedDelay = 5000)
//	public void check() {
//		System.out.println("working");
//	}
	
	@Scheduled(fixedDelay = 600000)
	public void deleteExpiredAccessTokens() {
		
//		System.out.println("Delete access tokens if expired");
		
		List<AccessToken> accessTokenList=accessTokenRepository.findAllByExpirationLessThan(LocalDateTime.now().minusHours(1));
		if(!accessTokenList.isEmpty()) {
			accessTokenRepository.deleteAll(accessTokenList);
		}
		
	}
	
	@Scheduled(fixedDelay = 600000)
	public void deleteExpiredRefreshTokens() {
//		System.out.println("Delete refresh tokens if expired");
		List<RefreshToken> refreshTokenList=refreshTokenRepository.findAllByExpirationLessThan(LocalDateTime.now().minusHours(1));
		if(!refreshTokenList.isEmpty()) {
			refreshTokenRepository.deleteAll(refreshTokenList);
		}
		
	}
	
	
}
