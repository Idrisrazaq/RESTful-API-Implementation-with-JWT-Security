package com.example.jwt.jwtconfig;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.jwt.repository.AccessTokenRepository;
import com.example.jwt.repository.RefreshTokenRepository;
import com.example.jwt.utility.GlobalException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	
	private JwtService jwtService;
	
	private UserDetailsService userDetailsService;
	
	private AccessTokenRepository accessTokenRepository;
	
	private RefreshTokenRepository refreshTokenRepository;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		
		//-------------------------------------------------------
		// method for extracting token from Authentication Header
//		final String authHeader=request.getHeader("Authorization");
//		
//		if(authHeader==null || !authHeader.startsWith("Bearer ")) {
//			filterChain.doFilter(request, response);
//			return;
//		}
//		
//		final String jwtToken=authHeader.substring(7);
//		
//		//extract from token
//		final String userEmail=jwtService.extractUserName(jwtToken);//jwtToken
//		
//		if(userEmail!=null && SecurityContextHolder.getContext().getAuthentication()==null) {
//			
//			System.out.println("Auth object created");
//			UserDetails userDetails=userDetailsService.loadUserByUsername(userEmail);
//			if(jwtService.isTokenValid(jwtToken, userDetails)) {//jwtToken
//				
//				UsernamePasswordAuthenticationToken authToken=
//						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//				
//				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//				SecurityContextHolder.getContext().setAuthentication(authToken);
//			
//			}
//		}
//		
//		filterChain.doFilter(request, response);
		
		//To extract token from cookies
		String at = null;
		String rt = null;
		if (request.getCookies() != null) {
			for (Cookie c : request.getCookies()) {
				if (c.getName().equals("at")) {

					at = c.getValue();
				}
				if (c.getName().equals("rt")) {
					rt = c.getValue();
				}
			}
		}
//		System.out.println(at+"access token");
//		System.out.println(rt+"refresh token");
		if (at != null && rt != null) {
			
			if (accessTokenRepository.existsByTokenAndIsBlocked(at, true)
					&& refreshTokenRepository.existsByTokenAndIsBlocked(rt, true)) {
				throw new GlobalException("invalid Credentials  please enter Correct Details....");
				}
			
			String userName = jwtService.extractUserName(at);
			String role = jwtService.getRole(at);
			UserDetails userDetails=userDetailsService.loadUserByUsername(userName);
			
			if (userName != null && SecurityContextHolder.getContext().getAuthentication() == null && role != null) {
				
				//Below condition not necessary
				if(jwtService.isTokenValid(at, userDetails)) {
					
					UsernamePasswordAuthenticationToken authToken=
							new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
					
					authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(authToken);
				
				}

			}

		}
		try {
			filterChain.doFilter(request, response);
		} catch (ExpiredJwtException e) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, " JWT token Expired..");

		} catch (JwtException e) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid JWT token");

		}
		
	}

}
