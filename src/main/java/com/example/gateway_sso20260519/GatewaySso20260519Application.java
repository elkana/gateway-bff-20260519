package com.example.gateway_sso20260519;

import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * OpenClaw BFF (Backend For Frontend) Gateway
 *
 * ARCHITECTURE OVERVIEW:
 * ┌─────────────┐ Session Cookie ┌─────────────────────┐
 * │ Browser │ ◄──────────────────────► │ BFF Gateway │
 * │ (Frontend) │ │ (This Application) │
 * └─────────────┘ └──────────┬──────────┘
 * │ Bearer Token
 * ▼
 * ┌─────────────────────┐
 * │ Downstream Services │
 * │ (Cashier, Products) │
 * └─────────────────────┘
 *
 * The browser NEVER sees: access_token, refresh_token, client_secret
 * The browser ONLY gets: HTTP-only session cookie (SESSION=xxx)
 *
 * @EnableRedisWebSession: stores Spring Session data (including OAuth2 tokens)
 *                         in Redis. This enables:
 *                         1. Horizontal scaling (multiple gateway instances
 *                         share session state)
 *                         2. Persistent sessions across gateway restarts
 *                         3. Centralized session invalidation (logout all
 *                         sessions)
 */
@SpringBootApplication
@EnableRedisWebSession
public class GatewaySso20260519Application {

	public static void main(String[] args) {
		SpringApplication.run(GatewaySso20260519Application.class, args);
	}
}

@RestController
@RequestMapping("/api/wallet")
class WalletController {

	@GetMapping("/balance")
	public Map<String, Object> balance(
			@AuthenticationPrincipal Jwt jwt) {

		return Map.of(
				"user", jwt.getSubject(),
				"goldBalance", 12.5);
	}
}