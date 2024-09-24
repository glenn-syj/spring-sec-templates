package com.glennsyj.auth.samples.controller;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
@Profile("oauth-session")
public class SessionAuthController {

	@GetMapping("/login")
	public String loginForm() {
		return "login"; // login.html 템플릿 반환
	}

	@PostMapping("/start-login")
	public String startLogin(@RequestParam("serverUrl") String serverUrl, HttpSession session) {
		// 서버 URL 정규화
		String normalizedServerUrl = normalizeServerUrl(serverUrl);

		// 환경 변수에서 클라이언트 자격 증명 가져오기
		String clientId = System.getenv("MM_CLIENT_ID");
		String clientSecret = System.getenv("MM_CLIENT_SECRET");

		if (clientId == null || clientSecret == null) {
			// 오류 처리: 클라이언트 자격 증명이 설정되지 않음
			return "redirect:/login?error=client_credentials_not_set";
		}

		session.setAttribute("serverUrl", serverUrl);

		// OAuth2 인증 엔드포인트로 리디렉션
		return "redirect:/oauth2/authorization/mattermost";
	}

	private String normalizeServerUrl(String serverUrl) {
		if (!serverUrl.startsWith("http")) {
			serverUrl = "https://" + serverUrl;
		}
		if (serverUrl.endsWith("/")) {
			serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
		}
		return serverUrl;
	}
}
