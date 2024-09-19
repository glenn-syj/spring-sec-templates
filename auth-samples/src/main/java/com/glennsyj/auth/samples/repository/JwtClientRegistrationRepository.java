package com.glennsyj.auth.samples.repository;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import com.glennsyj.auth.samples.config.ClientProperties;

@Component
public class JwtClientRegistrationRepository implements ClientRegistrationRepository {

	private final ClientProperties clientProperties;

	public JwtClientRegistrationRepository(ClientProperties clientProperties) {
		this.clientProperties = clientProperties;
	}

	@Override
	public ClientRegistration findByRegistrationId(String registrationId) {
		// 해당 registrationId에 맞는 클라이언트 정보를 불러옴
		ClientProperties.ClientRegistrationProperties properties = clientProperties.getClients().get(registrationId);

		if (properties == null) {
			throw new IllegalArgumentException("No client registration found for registrationId: " + registrationId);
		}

		// ClientRegistration을 구성하여 반환
		return ClientRegistration.withRegistrationId(registrationId)
			.clientId(properties.getClientId())
			.clientSecret(properties.getClientSecret())
			.authorizationUri(properties.getAuthorizationUri())
			.tokenUri(properties.getTokenUri())
			.userInfoUri(properties.getUserInfoUri())
			.redirectUri(properties.getRedirectUri())
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.scope(properties.getScope())
			.build();
	}
}

