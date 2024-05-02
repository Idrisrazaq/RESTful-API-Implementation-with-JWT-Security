package com.example.jwt.jwtconfig;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

//import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.example.jwt.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	@Value("${jwt.signinkey}")
	private String signInKey;
	
	@Value("${myapp.jwt.access.expiration}")
	private long accessExpiry;
	
	@Value("${myapp.jwt.refresh.expiration}")
	private long refreshExpiry;
	
	public String extractUserName(String jwtToken) {
		return extractClaim(jwtToken, Claims::getSubject);
	}
	
	public String generateToken(String userEmail, String userRole,long expiration) {
		return Jwts.builder()
				.setClaims(Map.of("role", userRole))
				.setSubject(userEmail)
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+expiration))
				.signWith(getSignInKey(),SignatureAlgorithm.HS256)
				.compact();
	}
	
	public boolean isTokenValid(String token, UserDetails userDetails) {
		String userName=extractUserName(token);
		return userName.equals(userDetails.getUsername()) && !isTokenExpired(token);
		
	}
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private <T> T extractClaim(String token,Function<Claims, T> claimResolver) {
		final Claims claims=extractAllClaims(token);
		return claimResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
		.setSigningKey(getSignInKey())
		.build()
		.parseClaimsJws(token)
		.getBody();
	}

	private Key getSignInKey() {
		byte[] key=Decoders.BASE64.decode(signInKey);
		return Keys.hmacShaKeyFor(key);
	}

	public String generateAccessToken(String userEmail, String userRole) {
		return generateToken(userEmail, userRole, accessExpiry);
	}

	public String generateRefreshToken(String userEmail, String userRole) {
		return generateToken(userEmail, userRole, refreshExpiry);
	}
	

	public String getRole(String token) {
		return extractAllClaims(token).get("role", String.class);
	}

	public Date getDate(String refreshToken) {
		return extractClaim(refreshToken, Claims::getIssuedAt);
	}
	
}
