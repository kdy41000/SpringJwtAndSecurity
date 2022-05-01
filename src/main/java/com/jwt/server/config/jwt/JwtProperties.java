package com.jwt.server.config.jwt;

public interface JwtProperties {

	String SUB = "jwt토큰";
	String SECRET = "DEVYoung";  // 서버만 알고있는 secret key
	int EXPIRATION_TIME = 864000000;
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
