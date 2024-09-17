package com.glennsyj.auth.samples.service;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.*;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.*;
import jakarta.servlet.http.*;

@Service
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();

	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// 현재 요청의 HttpServletRequest 가져오기
		ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (attrs == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"), "요청 컨텍스트를 찾을 수 없습니다.");
		}
		HttpServletRequest request = attrs.getRequest();
		HttpSession session = request.getSession(false);
		if (session != null) {
			ClientRegistration clientRegistration = (ClientRegistration) session.getAttribute("clientRegistration");
			if (clientRegistration != null) {
				OAuth2UserRequest updatedUserRequest = new OAuth2UserRequest(
					clientRegistration, userRequest.getAccessToken(), userRequest.getAdditionalParameters());
				return delegate.loadUser(updatedUserRequest);
			}
		}
		throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"), "클라이언트 등록 정보를 찾을 수 없습니다.");
	}
}
