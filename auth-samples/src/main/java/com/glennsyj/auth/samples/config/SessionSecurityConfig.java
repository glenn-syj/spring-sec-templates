package com.glennsyj.auth.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import com.glennsyj.auth.samples.repository.CustomClientRegistrationRepository;
import com.glennsyj.auth.samples.service.CustomOAuth2UserService;

@Configuration
@Profile("oauth-session")
public class SessionSecurityConfig {

	private final SessionOAuth2SuccessHandler sessionOAuth2SuccessHandler;
	private final SessionAuthorizationRequestResolver authorizationRequestResolver;
	private final CustomOAuth2UserService oAuth2UserService;
	private final CustomClientRegistrationRepository clientRegistrationRepository;
	private final SessionAuthenticationFailureHandler authenticationFailureHandler;

	public SessionSecurityConfig(SessionOAuth2SuccessHandler sessionOAuth2SuccessHandler,
		SessionAuthorizationRequestResolver authorizationRequestResolver,
		CustomOAuth2UserService customOAuth2UserService,
		CustomClientRegistrationRepository clientRegistrationRepository,
		SessionAuthenticationFailureHandler authenticationFailureHandler) {

		this.sessionOAuth2SuccessHandler = sessionOAuth2SuccessHandler;
		this.authorizationRequestResolver = authorizationRequestResolver;
		this.oAuth2UserService = customOAuth2UserService;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authenticationFailureHandler = authenticationFailureHandler;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
		http
			.authorizeHttpRequests(authorizeRequests ->
				authorizeRequests
					.requestMatchers("/", "/login/**", "/oauth2/**", "/templates/**", "/home").permitAll()  // OAuth2 관련 경로는 누구나 접근 가능
					.anyRequest().authenticated()  // 그 외 모든 요청은 인증 필요
			)
			.oauth2Login(oauth2 ->
				oauth2
					.loginPage("/login")  // 로그인 페이지 경로
					.successHandler(sessionOAuth2SuccessHandler)
					.failureHandler(authenticationFailureHandler)
					.clientRegistrationRepository(clientRegistrationRepository)
					.authorizationEndpoint(auth -> auth.authorizationRequestResolver(authorizationRequestResolver))
					.userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
					.defaultSuccessUrl("/home", true)  // 로그인 성공 시 이동할 URL
			)
			.logout(logout ->
				logout
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
					.logoutSuccessUrl("/home")
					.deleteCookies("JSESSIONID")
					.invalidateHttpSession(true)
			)
			.cors((cors) -> cors.configurationSource(corsConfigurationSource))
			.csrf((csrf) -> csrf.disable());

		return http.build();
	}
}
