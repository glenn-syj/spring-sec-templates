package com.glennsyj.auth.samples.config;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.glennsyj.auth.samples.repository.CustomClientRegistrationRepository;
import com.glennsyj.auth.samples.service.CustomOAuth2UserService;

@Configuration
public class SecurityConfig {

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> {
			web.ignoring()
				.requestMatchers("/login", "/home", "/start-login"); // 필터를 타면 안되는 경로
		};
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {

		final String[] allowedOrigins = {"http://localhost:8065", "http://127.0.0.1:8065"};

		final String[] allowedMethods = {"GET", "POST", "PUT", "DELETE", "OPTIONS"};

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
		configuration.setAllowedMethods(Arrays.asList(allowedMethods));
		configuration.setAllowCredentials(true);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
