package com.example.jwt.service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.function.ServerRequest.Headers;

import com.example.jwt.dto.AuthRequest;
import com.example.jwt.dto.AuthResponse;
import com.example.jwt.enums.UserRole;
import com.example.jwt.jwtconfig.JwtService;
import com.example.jwt.model.AccessToken;
import com.example.jwt.model.RefreshToken;
import com.example.jwt.model.User;
import com.example.jwt.repository.AccessTokenRepository;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.utility.GlobalException;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
public class AuthService {
	
	public AuthService(PasswordEncoder passwordEncoder, JwtService jwtService, AuthResponse authResponse,
			AuthenticationManager authenticationManager, UserRepository userRepository,
			AccessTokenRepository accessTokenRepository, RefreshTokenRepository refreshTokenRepository) {
		super();
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.authResponse = authResponse;
		this.authenticationManager = authenticationManager;
		this.userRepository = userRepository;
		this.accessTokenRepository = accessTokenRepository;
		this.refreshTokenRepository = refreshTokenRepository;
	}

	private PasswordEncoder passwordEncoder;
	
	private JwtService jwtService;
	
	private AuthResponse authResponse;
	
	private AuthenticationManager authenticationManager;
	
	private UserRepository userRepository;
	
	private AccessTokenRepository accessTokenRepository;
	
	private RefreshTokenRepository refreshTokenRepository;
	
	@Value("${myapp.jwt.access.expiration}")
	private long accessExpiry;
	
	@Value("${myapp.jwt.refresh.expiration}")
	private long refreshExpiry;


	public ResponseEntity<AuthResponse> registerUser(AuthRequest authRequest) {
		User user=new User();
		user.setUserEmail(authRequest.getUserEmail());
		user.setPassword(passwordEncoder.encode(authRequest.getPassword()));
		user.setUserName(authRequest.getUserName());
		user.setUserRole(UserRole.USER);
		userRepository.save(user);
		
		return ResponseEntity.ok(authResponse.builder()
				.userId(user.getUserId())
				.userName(user.getUserName())
				.userEmail(user.getUserEmail())
				.userRole(user.getUserRole())
				.build());
	}

	public ResponseEntity<AuthResponse> authenticate(AuthRequest authRequest, String accessToken, String refreshToken) throws Exception {
		
		if(accessToken!=null || refreshToken!=null) {
			System.out.println("user is already logged in");
			throw new GlobalException("User alreday logged in");
		}

		if (accessToken == null && refreshToken != null) {
			throw new GlobalException("your Access token expired please Regenerate Your AccessToken");
		}
		
		Authentication authenticate = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(authRequest.getUserEmail(), authRequest.getPassword())
				);
		
		if(!authenticate.isAuthenticated()) {
			throw new GlobalException("Invalid credentials");
		}
		
		HttpHeaders headers=new HttpHeaders();
				
		User user=userRepository.findByUserEmail(authRequest.getUserEmail()).get();
		
		AccessToken at=createAccessToken(user,headers);
		RefreshToken rt=createRefreshToken(user,headers);
		//use when token needs to be present in Authentication header
//		headers.set("Authorization", "Bearer "+at.getToken());
		at.setUser(user);
		rt.setUser(user);
		accessTokenRepository.save(at);
		refreshTokenRepository.save(rt);
		userRepository.save(user);
		
		AuthResponse resp=AuthResponse.builder().userEmail(user.getUserEmail())
								.userId(user.getUserId())
								.userName(user.getUserName())
								.userRole(user.getUserRole())
								.build();
		
		return ResponseEntity.ok().headers(headers).body(resp);
	}
	
	private RefreshToken createRefreshToken(User user, HttpHeaders headers) {
		
		String token = jwtService.generateRefreshToken(user.getUserEmail(), user.getUserRole().name());
		headers.add(HttpHeaders.SET_COOKIE, configureCookie("rt", token, accessExpiry));

		return RefreshToken.builder()
				.token(token)
				.expiration(LocalDateTime.now().plusHours(1))
				.isBlocked(false)
				.build();
	}

	private AccessToken createAccessToken(User user, HttpHeaders headers) {

		String token = jwtService.generateAccessToken(user.getUserEmail(), user.getUserRole().name());
		headers.add(HttpHeaders.SET_COOKIE, configureCookie("at", token, refreshExpiry));

		return AccessToken.builder()
				.token(token)
				.expiration(LocalDateTime.now().plusHours(1))
				.isBlocked(false)
				.build();
	}

	private String configureCookie(String name, String token, long maxAge) {
		return ResponseCookie
				.from(name,token)
				.domain("localhost")
				.path("/")
				.httpOnly(true)
				.secure(false)
				.maxAge(Duration.ofMillis(maxAge))
				.sameSite("Lax")
				.build().toString();
	}
	
	@Transactional
	public ResponseEntity<String> logout(String accessToken, String refreshToken) {
		if(accessToken==null) {
			throw new GlobalException("user already logged out");
		}
		
		HttpHeaders headers=new HttpHeaders();
		
		AccessToken at=accessTokenRepository.findByToken(accessToken);
		RefreshToken rt=refreshTokenRepository.findByToken(refreshToken);
		
		if(at!=null) {
			at.setBlocked(true);
			accessTokenRepository.save(at);
			removeAccess("at", headers);
		}
		if(rt!=null) {
			rt.setBlocked(true);
			refreshTokenRepository.save(rt);
			removeAccess("rt", headers);
		}
		
		return ResponseEntity.ok().headers(headers).body("User logged out successfully");
	}

	private void removeAccess(String name, HttpHeaders headers) {
		headers.add(HttpHeaders.SET_COOKIE, removeCookie(name));
	}

	private String removeCookie(String name) {
		return ResponseCookie.from(name, "")
				.domain("localhost")
				.path("/")
				.httpOnly(true)
				.secure(false)
				.maxAge(0)
				.sameSite("Lax")
				.build().toString();
	}

	public ResponseEntity<AuthResponse> generateNewToken(String accessToken, String refreshToken) {
		
		if(refreshToken==null || refreshTokenRepository.existsByTokenAndIsBlocked(refreshToken, true)) {
			throw new GlobalException("User is logged out and requires a login");
		}
		
		if(accessToken!=null) {
			AccessToken oldAccesstoken = accessTokenRepository.findByToken(accessToken);
			if(oldAccesstoken!=null) {
				oldAccesstoken.setBlocked(true);
				accessTokenRepository.save(oldAccesstoken);
			}
		}
		
		User user=refreshTokenRepository.findByToken(refreshToken).getUser();
		
		HttpHeaders headers=new HttpHeaders();
		
		if(jwtService.getDate(refreshToken).getDay()<(new Date().getDay())) {
			
			RefreshToken oldToken=refreshTokenRepository.findByToken(refreshToken);
			if(oldToken!=null) {
				oldToken.setBlocked(true);
				refreshTokenRepository.save(oldToken);
			}
			
			RefreshToken rt=this.createRefreshToken(user, headers);
			AccessToken at=this.createAccessToken(user, headers);
			rt.setUser(user);
			at.setUser(user);
			refreshTokenRepository.save(rt);
			accessTokenRepository.save(at);
			System.out.println("new refresh token and access token is generated");
		}else {
			AccessToken at=this.createAccessToken(user, headers);
			at.setUser(user);
			accessTokenRepository.save(at);
			headers.add(HttpHeaders.SET_COOKIE,configureCookie("rt", refreshToken, refreshExpiry));
			System.out.println("refresh token is still valid and new access token is generated");
		}
		
		
		return ResponseEntity.ok().headers(headers).body(AuthResponse.builder()
														.userEmail(user.getUserEmail())
														.userName(user.getUserName())
														.userRole(user.getUserRole())
														.build());
	}

}
