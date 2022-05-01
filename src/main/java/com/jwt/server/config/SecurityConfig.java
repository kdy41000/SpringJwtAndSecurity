package com.jwt.server.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

import com.jwt.server.config.jwt.JwtAuthenticationFilter;
import com.jwt.server.config.jwt.JwtAuthorizationFilter;
import com.jwt.server.filter.MyFilter1;
import com.jwt.server.filter.MyFilter3;
import com.jwt.server.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//http.addFilterBefore(new MyFilter3(), BasicAuthenticationFilter.class);  // http요청이 오면 시큐리티 필터(BasicAuthenticationFilter)가 실행되기 전에 MyFilter3 필터가 실행되도록 설정
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // 세션을 사용하지 않고 STATELESS서버로 만들겠다는 설정(JWT사용할거임)
		.and()
		.addFilter(corsFilter)   // @CrossOrigin(인증X), 시큐리티 필터에 등록(인증O)
		.formLogin().disable()   // form로그인 사용(X)
		.httpBasic().disable()   // httpBasic방식은 id,pw가 그대로 전달되기 때문에, Bearer JWT Web Token을 사용하여 구현해야 안전하므로 disable설정
		.addFilter(new JwtAuthenticationFilter(authenticationManager()))  // AuthenticationManager를 파라미터로 전달해야함
		.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))  // AuthenticationManager를 파라미터로 전달해야함
		// 권한별 api설정
		.authorizeRequests()
		// user
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		// manager
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		// admin
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		// other
		.anyRequest().permitAll();   // 이외 다른요청은 모두 허용
	}
	
}
