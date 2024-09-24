package com.glennsyj.auth.samples.config;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

public class CustomHttpServletRequestWrapper extends HttpServletRequestWrapper {

	private final Map<String, String[]> additionalParams;
	private final Map<String, String> additionalHeaders;

	public CustomHttpServletRequestWrapper(HttpServletRequest request) {
		super(request);
		this.additionalParams = new HashMap<>();
		this.additionalHeaders = new HashMap<>();
	}

	public void addParameter(String name, String value) {
		additionalParams.put(name, new String[] {value});
	}

	public void addHeader(String name, String value) {
		additionalHeaders.put(name, value);
	}

	@Override
	public String getParameter(String name) {
		// 추가된 파라미터가 있으면 반환
		if (additionalParams.containsKey(name)) {
			return additionalParams.get(name)[0];
		}
		// 그렇지 않으면 원래 요청의 파라미터 반환
		return super.getParameter(name);
	}

	@Override
	public Map<String, String[]> getParameterMap() {
		// 기존 파라미터와 새로운 파라미터를 합침
		Map<String, String[]> paramMap = new HashMap<>(super.getParameterMap());
		paramMap.putAll(additionalParams);
		return paramMap;
	}

	@Override
	public String getHeader(String name) {
		// 추가된 헤더가 있으면 해당 값 반환
		String headerValue = additionalHeaders.get(name);
		if (headerValue != null) {
			return headerValue;
		}
		// 그렇지 않으면 원래 요청의 헤더 반환
		return super.getHeader(name);
	}

	// getHeaderNames 오버라이드
	@Override
	public Enumeration<String> getHeaderNames() {
		// 기존 헤더와 추가된 헤더를 결합
		Vector<String> headerNames = new Vector<>();
		for (Enumeration<String> e = super.getHeaderNames(); e.hasMoreElements();) {
			headerNames.add(e.nextElement());
		}
		for (String headerName : additionalHeaders.keySet()) {
			headerNames.add(headerName);
		}
		return headerNames.elements();
	}

	// getHeaders 오버라이드 (같은 이름의 헤더가 여러 개 있을 수 있는 경우)
	@Override
	public Enumeration<String> getHeaders(String name) {
		Vector<String> values = new Vector<>();
		if (additionalHeaders.containsKey(name)) {
			values.add(additionalHeaders.get(name));
		}
		for (Enumeration<String> e = super.getHeaders(name); e.hasMoreElements();) {
			values.add(e.nextElement());
		}
		return values.elements();
	}
}
