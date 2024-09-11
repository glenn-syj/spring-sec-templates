package com.glennsyj.auth.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

	private final CustomOAuth2SuccessHandler customOAuth2SuccessHandler;

	// 생성자를 통한 의존성 주입
	public SecurityConfig(CustomOAuth2SuccessHandler customOAuth2SuccessHandler) {
		this.customOAuth2SuccessHandler = customOAuth2SuccessHandler;
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> {
			web.ignoring()
				.requestMatchers("/login", "/login/**", "/home"); // 필터를 타면 안되는 경로
		};
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorizeRequests ->
				authorizeRequests
					.requestMatchers("/", "/oauth2/**", "/templates/**", "/home").permitAll()  // OAuth2 관련 경로는 누구나 접근 가능
					.anyRequest().authenticated()  // 그 외 모든 요청은 인증 필요
			)
			.oauth2Login(oauth2 ->
				oauth2
					.loginPage("/login")  // 로그인 페이지 경로
					.successHandler(customOAuth2SuccessHandler)
					.defaultSuccessUrl("/home", true)  // 로그인 성공 시 이동할 URL
			)
			.logout(logout ->
				logout
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
					.logoutSuccessUrl("/home")
					.deleteCookies("JSESSIONID")
					.invalidateHttpSession(true)
			)
			.csrf((csrf) -> csrf.disable());;

		return http.build();
	}

}
