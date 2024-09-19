package com.glennsyj.auth.samples.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.glennsyj.auth.samples.entity.User;
import com.glennsyj.auth.samples.repository.UserRepository;

@Service
public class JwtOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

	private final UserRepository userRepository;

	public JwtOAuth2UserService(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();

	@Override
	@Transactional
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		// 기본 OAuth2UserService를 사용하여 사용자 정보 가져오기
		OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = delegate.loadUser(userRequest);

		// 사용자 정보 추출 (예: 이메일)
		String email = oAuth2User.getAttribute("email");
		String name = oAuth2User.getAttribute("name");

		if (email == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_email"), "Email not found from OAuth2 provider");
		}

		// ClientRegistration에서 authorization-uri 추출
		ClientRegistration clientRegistration = userRequest.getClientRegistration();
		String authorizationUri = clientRegistration.getProviderDetails().getAuthorizationUri();

		// authorization-uri로부터 도메인 추출
		String mattermostDomain = extractDomainFromUri(authorizationUri);

		// 사용자 존재 여부 확인 및 자동 등록
		User user = userRepository.findByUsername(email)
			.orElseGet(() -> {
				User newUser = new User();
				newUser.setUsername(email);
				newUser.setName(name);
				newUser.setProvider(clientRegistration.getRegistrationId()); // 또는 다른 제공자 정보
				newUser.setDomainAddress(mattermostDomain); // 도메인 설정
				newUser.setRoles(Collections.singleton("ROLE_USER")); // 기본 역할 설정
				return userRepository.save(newUser);
			});

		// 사용자 정보를 OAuth2User에 포함
		return new DefaultOAuth2User(
			user.getRoles().stream().map(SimpleGrantedAuthority::new).toList(),
			oAuth2User.getAttributes(),
			"email"
		);
	}

	private String extractDomainFromUri(String uri) {
		try {
			URI parsedUri = new URI(uri);
			return parsedUri.getHost();
		} catch (URISyntaxException e) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_uri"), "Invalid authorization URI", e);
		}
	}
}
