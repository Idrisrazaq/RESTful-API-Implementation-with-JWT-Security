package com.example.jwt.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/v1/demo")
public class UserController {
	
	@GetMapping("/test")
	public ResponseEntity<String> testEndPoint(){
		return ResponseEntity.ok("user authenticated");
	}
	
	@GetMapping("/test2")
	public ResponseEntity<String> testEndPoint2(
			@CookieValue(name="at",required = false)String accessToken,
			@CookieValue(name="rt",required = false)String refreshToken){
		return ResponseEntity.ok("user authenticated");
	}
	
}
