package com.jwt.server.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.server.config.auth.PrincipalDetails;
import com.jwt.server.model.User;
import com.jwt.server.repository.UserRepository;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탄다. (인가)
public class JwtAuthorizationFilter extends BasicAuthenticationFilter implements JwtProperties {

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}

	// 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 타게됨.
	// 이 프로젝트에서는 "/api/v1/user/**", "/api/v1/manager/**", "/api/v1/admin/**" 요청 시 해당 필터를 타게됨
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨.");
		
		String jwtHeader = request.getHeader("Authorization");
		System.out.println("jwtHeader: " + jwtHeader);
		
		// header가 있는지 확인, "Bearer " 로 시작하는지 확인 
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		// Jwt 토큰을 검증을 해서 정상적인 사용자인지 확인
		String jwtToken = jwtHeader.replace(TOKEN_PREFIX, "");
		
		String username = JWT.require(Algorithm.HMAC512(SECRET)).build().verify(jwtToken).getClaim("username").asString();
		
		//서명이 정상적으로 됨
		if(username != null) {
			System.out.println("jwtToken verified.");
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			// Jwt토큰 서명을 통해서 서명이 되었으므로 강제로 Authentication객체를 만들어 인증시킴
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, true, principalDetails.getAuthorities());
		
			// 강제로 시큐리티의 세션에 접근하여 Authentication객체를 저장.
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
		
	}
	
}
