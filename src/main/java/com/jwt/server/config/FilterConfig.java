package com.jwt.server.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.jwt.server.filter.MyFilter1;
import com.jwt.server.filter.MyFilter2;

@Configuration
public class FilterConfig {

	// 시큐리티 필터가 동작된 후에 실행됨(가장 먼저 실행되어야 하면 SecurityConfig파일에 addFilterBefore로 설정해야됨
	@Bean  // IoC에 등록
	public FilterRegistrationBean<MyFilter1> filter1() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
		bean.addUrlPatterns("/*");
		bean.setOrder(0);  // 낮은 번호가 필터중에서 가장 먼저 실행됨
		return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
		bean.addUrlPatterns("/*");
		bean.setOrder(1);
		return bean;
	}
	
}
