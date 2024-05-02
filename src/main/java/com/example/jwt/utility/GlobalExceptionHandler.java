package com.example.jwt.utility;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

@RestControllerAdvice
public class GlobalExceptionHandler {
	
	@ExceptionHandler(value = GlobalException.class)
	public ResponseEntity handleGlobalException(GlobalException exception) {
		return new ResponseEntity(exception.getMessage(), HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(value = ExpiredJwtException.class)
	public ResponseEntity jwtTokenExpiredException(ExpiredJwtException exception) {
		return new ResponseEntity(exception.getMessage(), HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(value = JwtException.class)
	public ResponseEntity jwtTokenInvalidException(JwtException exception) {
		return new ResponseEntity(exception.getMessage(), HttpStatus.BAD_REQUEST);
	}
	
	@ExceptionHandler(value = InternalAuthenticationServiceException.class)
	public ResponseEntity internalAuthException(InternalAuthenticationServiceException exception) {
		return new ResponseEntity(exception.getMessage(), HttpStatus.BAD_REQUEST);
	}
	
}
