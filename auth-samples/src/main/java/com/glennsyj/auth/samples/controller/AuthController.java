package com.glennsyj.auth.samples.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;

@Controller
public class AuthController {

	@GetMapping("/login")
	public String loginForm() {
		return "login"; // login.html 템플릿 반환
	}

	@PostMapping("/start-login")
	public String startLogin(@RequestParam("serverUrl") String serverUrl,
		@RequestParam("clientId") String clientId,
		@RequestParam("clientSecret") String clientSecret,
		HttpSession session) {
		// 세션에 값 저장
		session.setAttribute("mattermost_server_url", serverUrl);
		session.setAttribute("mattermost_client_id", clientId);
		session.setAttribute("mattermost_client_secret", clientSecret);

		// OAuth2 인증 엔드포인트로 리디렉션
		return "redirect:/login/oauth2/code/mattermost";
	}
}
