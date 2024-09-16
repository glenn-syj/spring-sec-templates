package com.glennsyj.auth.samples.config;

import java.util.UUID;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private final String authorizationRequestBaseUri; // "/oauth2/authorization"

	public CustomAuthorizationRequestResolver(String authorizationRequestBaseUri) {
		this.authorizationRequestBaseUri = authorizationRequestBaseUri;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		String requestUri = request.getRequestURI();
		if (!requestUri.equals(authorizationRequestBaseUri + "/mattermost")) {
			return null;
		}

		HttpSession session = request.getSession(false);
		if (session == null) {
			return null;
		}

		String serverUrl = (String) session.getAttribute("mattermost_server_url");

		// TODO: this should be done in an applicaiton level, not in user informs.
		String clientId = (String) session.getAttribute("mattermost_client_id");
		String clientSecret = (String) session.getAttribute("mattermost_client_secret");

		if (serverUrl == null || clientId == null || clientSecret == null) {
			return null;
		}

		// ClientRegistration 생성
		ClientRegistration clientRegistration = buildClientRegistration(serverUrl, clientId, clientSecret);

		// 세션에 저장하여 토큰 교환 시 사용
		session.setAttribute("clientRegistration", clientRegistration);

		// OAuth2AuthorizationRequest 생성
		OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
			.clientId(clientRegistration.getClientId())
			.redirectUri("{baseUrl}/login/oauth2/code/mattermost")
			.scopes(clientRegistration.getScopes())
			.state(UUID.randomUUID().toString())
			.build();

		return authorizationRequest;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		return resolve(request);
	}

	private ClientRegistration buildClientRegistration(String serverUrl, String clientId, String clientSecret) {
		String authorizationUri = serverUrl + "/oauth/authorize";
		String tokenUri = serverUrl + "/oauth/access_token";
		String userInfoUri = serverUrl + "/api/v4/users/me";
		String redirectUriTemplate = "{baseUrl}/login/oauth2/code/mattermost";

		return ClientRegistration.withRegistrationId("mattermost")
			.clientId(clientId)
			.clientSecret(clientSecret)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(redirectUriTemplate)
			.scope("email", "profile")
			.authorizationUri(authorizationUri)
			.tokenUri(tokenUri)
			.userInfoUri(userInfoUri)
			.userNameAttributeName("username") // 사용자 정보 응답에 따라 조정
			.clientName("Mattermost")
			.build();
	}
}

