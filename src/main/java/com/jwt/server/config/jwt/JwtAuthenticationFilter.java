package com.jwt.server.config.jwt;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.server.config.auth.PrincipalDetails;
import com.jwt.server.model.User;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password를 post전송하면
// UsernamePasswordAuthenticationFilter가 동작함
// 해당 파일에서는 로그인 인증 후 인증되었으면 JWT토큰 생성 후 응답하는 기능을 한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter implements JwtProperties {

	private final AuthenticationManager authenticationManager;
	
	// login요청을 하면 로그인 시도를 위해서 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws org.springframework.security.core.AuthenticationException {
		System.out.println("JwtAuthenticationFilter: 로그인 시도중");
	
		try {
			// 1.username, password를 받는다.(json형태로 넘어온 값을 파싱함)
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println("user:" + user);
			
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 2.정상인지 로그인 시도를 해본다. authenticate()함수 호출시 PrincipalDetailsService의 loadUserByUsername() 함수가 실행된 후 정상이면 Authentication이 리턴됨.
			// DB에 있는 username과 password가 일치한다.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			// 3.PrincipalDetails를 세션에 담는다.(권한관리를 위해서, 필요없으면 생략해도 된다.)
			// authentication 객체가 session영역에 저장됨 => 로그인이 되었다는뜻
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
			System.out.println("로그인 완료됨 : " + principalDetails.getUser().getUsername());
			// authentication 객체가 session영역에 저장을 해야하고 그 방법이 return해주면 됨.
			// 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임.
			// 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 권한 처리때문에 세션에 넣어줌
			return authentication;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	// 4. Jwt토큰을 생성한다. (attemptAuthentication실행 후 인증이 정상적으로 되었으면 successfulAuthentication함수가 실행된다.)
	// JWT Token 생성해서 response에 담아주기(java-jwt 라이브러리 사용)
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임.");
		PrincipalDetails principalDetailis = (PrincipalDetails) authResult.getPrincipal();
		
		// 토큰 만료시간 SimpleDateFormat으로 출력하여 확인
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		String tokenExpireDate = sdf.format(System.currentTimeMillis()+EXPIRATION_TIME);
		System.out.println("tokenExpireDate: " + tokenExpireDate);
		
		// RSA방식은 아니고 Hash암호방식
		String jwtToken = JWT.create()
					.withSubject(SUB)
					.withExpiresAt(new Date(System.currentTimeMillis()+EXPIRATION_TIME))  //만료시간: 10분(보안이슈 때문에 짧게 설정하는 것이 좋다.)
					.withClaim("id", principalDetailis.getUser().getId())
					.withClaim("username", principalDetailis.getUser().getUsername())
					.sign(Algorithm.HMAC512(SECRET));
			
		// Header.Payload.Signature 형태로 생성된 JWT토큰을 Header에 담아서 응답한다.
		response.addHeader(HEADER_STRING, TOKEN_PREFIX+jwtToken);
	}
		
}
