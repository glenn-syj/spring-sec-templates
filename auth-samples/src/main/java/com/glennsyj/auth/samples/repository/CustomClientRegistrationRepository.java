package com.glennsyj.auth.samples.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import jakarta.servlet.http.*;

@Component
public class CustomClientRegistrationRepository implements ClientRegistrationRepository {

	private static final Logger logger = LoggerFactory.getLogger(CustomClientRegistrationRepository.class);

	@Override
	public ClientRegistration findByRegistrationId(String registrationId) {
		if (!"mattermost".equals(registrationId)) {
			return null;
		}
		// RequestContextHolder를 사용하여 현재 요청의 HttpServletRequest를 가져옵니다.
		ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
		if (attrs == null) {
			logger.debug("attrs are null.");
			return null; // 요청 컨텍스트가 없으면 null 반환
		}
		HttpServletRequest request = attrs.getRequest();
		HttpSession session = request.getSession(true);
		if (session != null) {
			logger.debug("ClientRegistration found.");
			return (ClientRegistration) session.getAttribute("clientRegistration");
		}

		logger.debug("ClientRegistration not found in session.");
		return null;
	}
}



