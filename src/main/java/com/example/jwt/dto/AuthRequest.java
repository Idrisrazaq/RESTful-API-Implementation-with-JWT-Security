package com.example.jwt.dto;

import lombok.Data;

@Data
public class AuthRequest {
	private String userName;
	private String userEmail;
	private String password;
}
