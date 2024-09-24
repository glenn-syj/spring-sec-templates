package com.glennsyj.auth.samples.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class ClientProperties {

	private Map<String, ClientRegistrationProperties> registration = new HashMap<>();
	private Map<String, ProviderProperties> provider = new HashMap<>();

	public Map<String, ClientRegistrationProperties> getRegistration() {
		return registration;
	}

	public Map<String, ProviderProperties> getProvider() {
		return provider;
	}

	@Getter
	@Setter
	public static class ClientRegistrationProperties {
		private String clientId;
		private String clientSecret;
		private String scope;
		private String authorizationGrantType;
		private String redirectUri;
		private String clientName;
		private String clientAuthenticationMethod;
	}

	@Getter
	@Setter
	public static class ProviderProperties {
		private String authorizationUri;
		private String tokenUri;
		private String userInfoUri;
		private String userNameAttribute;
	}
}