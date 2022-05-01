package com.jwt.server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.server.config.auth.PrincipalDetails;
import com.jwt.server.model.User;
import com.jwt.server.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class RestApiController {

	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	// 모든 사람이 접근 가능
	@GetMapping("/home")
	public String home() {
		return "<h1>home</h1>";
	}
	
	@PostMapping("/join")
	public String join(@RequestBody User user) {
		System.out.println("======= join ============");
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입완료";
	}
	
	// user, manager, admin 접근가능
	@GetMapping("/api/v1/user")
	public String user(Authentication authentication) {
		PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
		System.out.println("authentication : " + principalDetails.getUsername());
		return "user";
	}
	
	// manager, admin 접근가능
	@GetMapping("/api/v1/manager")
	public String manager() {
		return "manager";
	}
	
	// admin 접근가능
	@GetMapping("/api/v1/admin")
	public String admin() {
		return "admin";
	}

}
