package com.glennsyj.auth.samples.config;

import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import com.glennsyj.auth.samples.repository.JwtClientRegistrationRepository;

import jakarta.servlet.http.HttpServletRequest;

@Component
@Profile("oauth-jwt")
public class JwtAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private final OAuth2AuthorizationRequestResolver defaultResolver;

	public JwtAuthorizationRequestResolver(JwtClientRegistrationRepository clientRegistrationRepository) {
		this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorize");
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
		return customizeAuthorizationRequest(authorizationRequest);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
		return customizeAuthorizationRequest(authorizationRequest);
	}

	private OAuth2AuthorizationRequest customizeAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
		// 동적 파라미터 추가 또는 수정
		return OAuth2AuthorizationRequest.from(authorizationRequest)
			.additionalParameters(params -> {
				params.put("custom_param", "custom_value");
			})
			.build();
	}
}

