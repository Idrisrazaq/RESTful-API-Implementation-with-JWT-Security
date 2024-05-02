package com.example.jwt.utility;

public class GlobalException extends RuntimeException{

	private String message;
	
	public GlobalException(String message) {
		this.message=message;
	}
	@Override
	public String getMessage() {
		return message;
	}
}
