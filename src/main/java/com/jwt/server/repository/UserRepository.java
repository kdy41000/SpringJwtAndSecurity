package com.jwt.server.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.jwt.server.model.User;

public interface UserRepository extends JpaRepository<User, Long>{

	public User findByUsername(String username);
	
}
