package com.jwt.server.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;

@Data
@Entity
@Table(name="TB_USER")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private long id;
	private String password;
	private String username;
	private String roles;  // USER, ADMIN
	
	public List<String> getRoleList() {
		if(this.roles.length() > 0) {
			return Arrays.asList(this.roles.split(","));
		}
		return new ArrayList<>();
	}
	
}