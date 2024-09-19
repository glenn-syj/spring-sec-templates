package com.glennsyj.auth.samples.config;

import java.util.Collections;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;

import com.glennsyj.auth.samples.repository.CustomClientRegistrationRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Component
@Profile("oauth-session")
public class SessionAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

	private static final Logger logger = LoggerFactory.getLogger(SessionAuthorizationRequestResolver.class);

	private final ClientRegistrationRepository clientRegistrationRepository;
	private final String authorizationRequestBaseUri = "/oauth2/authorization";

	public SessionAuthorizationRequestResolver(CustomClientRegistrationRepository clientRegistrationRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {

		logger.debug("no registrationId");
		return resolve(request, null);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
		if (!isAuthorizationRequest(request)) {
			return null;
		}

		String serverUrl = request.getParameter("serverUrl");
		if (serverUrl == null) {
			// 세션에서 서버 URL 가져오기
			HttpSession session = request.getSession(false);
			if (session != null) {
				serverUrl = (String) session.getAttribute("serverUrl");
			}
		} else {
			// 서버 URL을 세션에 저장
			HttpSession session = request.getSession();
			session.setAttribute("serverUrl", serverUrl);
		}

		if (serverUrl == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"), "Mattermost 서버 주소가 필요합니다.");
		}

		// 서버 URL 정규화
		serverUrl = normalizeServerUrl(serverUrl);

		// 환경 변수에서 클라이언트 자격 증명 가져오기
		String clientId = System.getenv("MM_CLIENT_ID");
		logger.info("clientId: {}", clientId);
		String clientSecret = System.getenv("MM_CLIENT_SECRET");
		logger.info("clientId: {}", clientSecret);

		if (clientId == null || clientSecret == null) {
			throw new IllegalStateException("환경 변수 MATTERMOST_CLIENT_ID와 MATTERMOST_CLIENT_SECRET을 설정해야 합니다.");
		}

		// ClientRegistration 생성
		ClientRegistration clientRegistration = buildClientRegistration(serverUrl, clientId, clientSecret);

		// 세션에 ClientRegistration 저장
		HttpSession session = request.getSession();
		session.setAttribute("clientRegistration", clientRegistration);

		// OAuth2AuthorizationRequest 생성
		return OAuth2AuthorizationRequest.authorizationCode()
			.clientId(clientRegistration.getClientId())
			.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
			.redirectUri(clientRegistration.getRedirectUri())
			.scopes(clientRegistration.getScopes())
			.state(UUID.randomUUID().toString())
			.additionalParameters(Collections.emptyMap())
			.attributes(attrs -> attrs.put(OAuth2ParameterNames.REGISTRATION_ID, clientRegistration.getRegistrationId()))
			.build();
	}

	private boolean isAuthorizationRequest(HttpServletRequest request) {
		return request.getRequestURI().startsWith(authorizationRequestBaseUri);
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

	private ClientRegistration buildClientRegistration(String serverUrl, String clientId, String clientSecret) {
		String registrationId = "mattermost";
		String authorizationUri = serverUrl + "/oauth/authorize";
		String tokenUri = serverUrl + "/oauth/access_token";
		String userInfoUri = serverUrl + "/api/v4/users/me";
		String redirectUriTemplate = "http://localhost:8080/login/oauth2/code/" + registrationId;

		logger.debug("buildClientRegistration done.");

		return ClientRegistration.withRegistrationId(registrationId)
			.clientId(clientId)
			.clientSecret(clientSecret)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri(redirectUriTemplate)
			.scope("email", "profile")
			.authorizationUri(authorizationUri)
			.tokenUri(tokenUri)
			.userInfoUri(userInfoUri)
			.userNameAttributeName("username")
			.clientName("Mattermost")
			.build();
	}
}
