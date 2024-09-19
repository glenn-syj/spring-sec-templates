package com.glennsyj.auth.samples.filter;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.glennsyj.auth.samples.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtUtil jwtUtil;
	private final UserDetailsService userDetailsService;

	public JwtAuthenticationFilter(JwtUtil jwtUtil, UserDetailsService customUserDetailsService) {
		this.jwtUtil = jwtUtil;
		this.userDetailsService = customUserDetailsService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws
		ServletException, IOException {

		final String authHeader = request.getHeader("Authorization");
		String username = null;
		String accessToken = null;

		if (authHeader == null || !authHeader.startsWith("Bearer ")) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or missing Authorization header.");
			return;
		}

		accessToken = authHeader.substring(7); // "Bearer " 이후의 JWT 추출
		try {
			username = jwtUtil.extractUsername(accessToken);
		} catch (Exception e) {
			logger.error("JWT 추출 실패: " + e.getMessage());
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token.");
			return;
		}

		if (username == null) {
			throw new IllegalArgumentException("No username found in the token.");
		}

		UserDetails userDetails = null;
		try {
			userDetails = userDetailsService.loadUserByUsername(username);
		} catch (UsernameNotFoundException e) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not found.");
			return;
		}

		if (jwtUtil.validateToken(accessToken, userDetails.getUsername())) {
			UsernamePasswordAuthenticationToken authenticationToken =
				new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

			authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			// SecurityContext에 인증 정보 설정
			SecurityContextHolder.getContext().setAuthentication(authenticationToken);
		}

		filterChain.doFilter(request, response); // 요청 처리 계속
	}


}
