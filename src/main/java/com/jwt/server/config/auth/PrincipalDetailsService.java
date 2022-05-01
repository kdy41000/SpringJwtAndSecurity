package com.jwt.server.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt.server.model.User;
import com.jwt.server.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 요청이 오면 실행됨
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("PrincipalDetailsService -> PrincipalDetailsService");
		User userEntity = userRepository.findByUsername(username);
		System.out.println("userEntity: " + userEntity);
		return new PrincipalDetails(userEntity);
	}

	
}
