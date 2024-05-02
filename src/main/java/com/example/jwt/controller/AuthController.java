package com.example.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import com.example.jwt.dto.AuthRequest;
import com.example.jwt.dto.AuthResponse;
import com.example.jwt.service.AuthService;

import lombok.AllArgsConstructor;

@Controller
@RequestMapping("/api/v1/auth")
@AllArgsConstructor
public class AuthController {
	
	private AuthService authService;
	
	@PostMapping("/register")
	public ResponseEntity<AuthResponse> registerUser(@RequestBody AuthRequest authRequest){
		return authService.registerUser(authRequest);
	}
	@PostMapping("/authenticate")
	public  ResponseEntity<AuthResponse> authenticate(@RequestBody AuthRequest authRequest,
			@CookieValue(name="at",required = false)String accessToken,
			@CookieValue(name="rt",required = false)String refreshToken) throws Exception {
		return authService.authenticate(authRequest,accessToken,refreshToken);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<String> logout(
			@CookieValue(name="at",required = false)String accessToken,
			@CookieValue(name="rt",required = false)String refreshToken){
		return authService.logout(accessToken,refreshToken);
	}
	
	@PostMapping("/login/refresh")
	public ResponseEntity<AuthResponse> generateNewToken(
			@CookieValue(name = "at",required = false)String accessToken,
			@CookieValue(name = "rt",required = false)String refreshToken){
		return authService.generateNewToken(accessToken,refreshToken);
	}
	
	
	
}
