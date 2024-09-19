package com.glennsyj.auth.samples.config;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Profile("oauth-jwt")
public class JwtAuthenticationFailureHandler implements AuthenticationFailureHandler {
	private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFailureHandler.class);

	@Override
	public void onAuthenticationFailure(HttpServletRequest request,
		HttpServletResponse response,
		AuthenticationException exception) throws IOException, ServletException {
		logger.error("Authentication failed: {}", exception.getMessage(), exception);
		response.sendRedirect("/login?error=" + exception.getMessage());
	}

}
