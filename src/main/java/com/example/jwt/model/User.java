package com.example.jwt.model;

import java.util.ArrayList;
import java.util.List;

import com.example.jwt.enums.UserRole;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@Builder
@AllArgsConstructor
public class User {
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Integer userId;
	private String userName;
	private String userEmail;
	private String password;
	private UserRole userRole;
	
	@OneToMany(mappedBy = "user")
	List<AccessToken> accessTokenList=new ArrayList<AccessToken>();
	
	@OneToMany(mappedBy = "user")
	List<RefreshToken> refreshTokenList=new ArrayList<RefreshToken>();

}
