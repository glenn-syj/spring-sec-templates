package com.glennsyj.auth.samples.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomOAuth2SuccessHandler implements AuthenticationSuccessHandler {

	private static final Logger logger = LoggerFactory.getLogger(CustomOAuth2SuccessHandler.class);

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws
		IOException {
		OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
		String username = oauthUser.getAttribute("username");
		String email = oauthUser.getAttribute("email");

		logger.debug("OAuth2 로그인 성공 - 사용자명: {}, 이메일: {}", username, email);
	}
}
