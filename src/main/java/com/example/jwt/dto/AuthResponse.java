package com.example.jwt.dto;

import org.springframework.stereotype.Component;

import com.example.jwt.enums.UserRole;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Component
public class AuthResponse {
	private Integer userId;
	private String userName;
	private String userEmail;
	private UserRole userRole;
//	String token;
	
}
