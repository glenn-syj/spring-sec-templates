package com.glennsyj.auth.samples.config;

import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;

@Configuration
@ConfigurationProperties(prefix = "oauth2.clients")

public class ClientProperties {

	private Map<String, ClientRegistrationProperties> clients = new HashMap<>();

	public Map<String, ClientRegistrationProperties> getClients() {
		return clients;
	}

	@Getter
	public static class ClientRegistrationProperties {
		private String clientId;
		private String clientSecret;
		private String authorizationUri;
		private String tokenUri;
		private String userInfoUri;
		private String redirectUri;
		private String scope;
	}
}

