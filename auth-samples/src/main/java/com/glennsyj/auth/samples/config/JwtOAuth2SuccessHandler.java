package com.glennsyj.auth.samples.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.glennsyj.auth.samples.util.JwtUtil;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Profile("oauth-jwt")
public class JwtOAuth2SuccessHandler implements AuthenticationSuccessHandler {

	private final JwtUtil jwtUtil;

	public JwtOAuth2SuccessHandler(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request,
		HttpServletResponse response,
		Authentication authentication) throws IOException, ServletException {
		OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

		// 사용자의 이메일 또는 고유 식별자를 기반으로 JWT 생성
		String email = oAuth2User.getAttribute("email");

		// JWT에 포함할 클레임 설정 (역할, 권한 등)
		Map<String, Object> claims = new HashMap<>();
		claims.put("email", email);

		// JWT 발급
		String jwt = jwtUtil.generateToken(claims, email);

		// JWT를 응답 헤더 또는 바디로 클라이언트에 전달
		response.addHeader("Authorization", "Bearer " + jwt);

		// JSON으로 응답할 경우:
        /*
        response.setContentType("application/json");
        response.getWriter().write("{\"token\": \"" + jwt + "\"}");
        response.getWriter().flush();
        */
	}

}
