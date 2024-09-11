package com.glennsyj.auth.samples.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

	@GetMapping("/home")
	public String index() {
		return "index";  // index.html 반환
	}

	@GetMapping("/login")
	public String login() {
		return "login";  // index.html 반환
	}

	@GetMapping("/login/oauth2/code/mattermost")
	public String callback() {
		return "index";  // index.html 반환
	}
}
