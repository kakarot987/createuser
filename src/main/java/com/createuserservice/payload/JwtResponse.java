package com.createuserservice.payload;

import java.util.List;

public class JwtResponse {
	private String token;
	private String type = "Bearer";
	private Long userId;

	public JwtResponse(Long userId,String accessToken) {
		this.userId = userId;
		this.token = accessToken;
	}


	public String getAccessToken() {
		return token;
	}

	public void setAccessToken(String accessToken) {
		this.token = accessToken;
	}

	public String getTokenType() {
		return type;
	}

	public void setTokenType(String tokenType) {
		this.type = tokenType;
	}


	public Long getUserId() {
		return userId;
	}

	public void setUserId(Long userId) {
		this.userId = userId;
	}
}