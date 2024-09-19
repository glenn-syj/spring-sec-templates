package com.glennsyj.auth.samples.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import com.glennsyj.auth.samples.filter.JwtAuthenticationFilter;
import com.glennsyj.auth.samples.repository.JwtClientRegistrationRepository;
import com.glennsyj.auth.samples.service.CustomOAuth2UserService;
import com.glennsyj.auth.samples.service.CustomUserDetailsService;

@Configuration
@Profile("oauth-jwt")
public class JwtSecurityConfig {

	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;
	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final AuthenticationFailureHandler authenticationFailureHandler;
	private final UserDetailsService userDetailsService;
	private final JwtAuthenticationFilter jwtAuthenticationFilter;

	public JwtSecurityConfig(JwtOAuth2SuccessHandler jwtOAuth2SuccessHandler,
		JwtAuthorizationRequestResolver jwtAuthorizationRequestResolver,
		CustomOAuth2UserService customOAuth2UserService,
		JwtClientRegistrationRepository jwtClientRegistrationRepository,
		JwtAuthenticationFailureHandler authenticationFailureHandler,
		CustomUserDetailsService customUserDetailsService,
		JwtAuthenticationFilter jwtAuthenticationFilter) {

		this.authenticationSuccessHandler = jwtOAuth2SuccessHandler;
		this.authorizationRequestResolver = jwtAuthorizationRequestResolver;
		this.oAuth2UserService = customOAuth2UserService;
		this.clientRegistrationRepository = jwtClientRegistrationRepository;
		this.authenticationFailureHandler = authenticationFailureHandler;
		this.userDetailsService = customUserDetailsService;
		this.jwtAuthenticationFilter = jwtAuthenticationFilter;
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
					.loginPage("/" + getLogin())  // 로그인 페이지 경로
					.successHandler(authenticationSuccessHandler)
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
			.csrf((csrf) -> csrf.disable())
			.sessionManagement((session) -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			);

		http
			.userDetailsService(userDetailsService);

		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	private static String getLogin() {
		return "login";
	}
}
