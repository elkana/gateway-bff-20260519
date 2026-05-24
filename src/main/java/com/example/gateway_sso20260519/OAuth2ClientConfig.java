package com.example.gateway_sso20260519;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * OAUTH2 AUTHORIZED CLIENT CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This is the heart of the token management system. It configures:
 *
 * 1. WHERE TOKENS ARE STORED
 * → WebSessionServerOAuth2AuthorizedClientRepository stores the
 * OAuth2AuthorizedClient (access token + refresh token) in the
 * WebSession, which is persisted to Redis by Spring Session.
 *
 * → The browser only receives a SESSION cookie (HTTP-only).
 * The tokens are INSIDE the session data in Redis.
 *
 * 2. HOW TOKENS ARE AUTO-REFRESHED
 * → ReactiveOAuth2AuthorizedClientManager checks if the access token
 * is expired before each request.
 * → If expired, it automatically calls Keycloak's token endpoint with
 * the refresh_token to get a new access_token.
 * → The new tokens are saved back to Redis.
 * → The frontend NEVER knows any of this happened.
 *
 * 3. HOW THE TokenRelay= GATEWAY FILTER WORKS
 * → Spring Cloud Gateway's TokenRelay filter calls the authorized client
 * manager to get a valid (possibly freshly refreshed) token, then
 * injects it as "Authorization: Bearer <token>" on the downstream request.
 * ═══════════════════════════════════════════════════════════════════════════
 */
@Slf4j
@Configuration
public class OAuth2ClientConfig {

    /**
     * AUTHORIZED CLIENT REPOSITORY
     *
     * Stores OAuth2AuthorizedClient objects in the WebSession.
     * Spring Session automatically persists this to Redis.
     *
     * Data flow:
     * Login → tokens stored here → Redis → retrieved per-request → TokenRelay
     * injects to downstream
     */
    @Bean
    public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    /**
     * AUTHORIZED CLIENT MANAGER (with automatic token refresh)
     *
     * This is the component that:
     * 1. Retrieves the stored OAuth2AuthorizedClient for the current user
     * 2. Checks if the access token is expired
     * 3. If expired: requests a new access token using the refresh token
     * (this is a server-to-server call to Keycloak — browser not involved)
     * 4. Saves the new tokens back to the session (Redis)
     * 5. Returns a valid OAuth2AuthorizedClient with a fresh access token
     *
     * AUTO-REFRESH MECHANISM:
     * ─────────────────────────
     * The ReactiveRefreshTokenOAuth2AuthorizedClientProvider handles the
     * token refresh. It uses the OAuth2 Refresh Token Grant:
     *
     * POST /realms/los-realm/protocol/openid-connect/token
     * grant_type=refresh_token
     * refresh_token=<stored_refresh_token>
     * client_id=cashier-1-client
     * client_secret=secret
     *
     * Keycloak responds with a new access_token (and optionally a new
     * refresh_token).
     * All of this happens inside the gateway — zero frontend involvement.
     */
    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

        // Configure providers for different grant types
        ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = ReactiveOAuth2AuthorizedClientProviderBuilder
                .builder()
                // Handles initial Authorization Code Flow login
                .authorizationCode()
                // Handles automatic token refresh (most important for BFF)
                .refreshToken(refreshToken -> refreshToken
                        // Refresh the token if it expires within the next 30 seconds
                        // This prevents requests from failing at the last second
                        .clockSkew(java.time.Duration.ofSeconds(30)))
                // Handles Client Credentials flow for service-to-service calls
                .clientCredentials()
                .build();

        DefaultReactiveOAuth2AuthorizedClientManager manager = new DefaultReactiveOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository);

        manager.setAuthorizedClientProvider(authorizedClientProvider);

        // Context attributes provider: passes the ServerWebExchange so the
        // manager can save updated tokens back to the session (Redis)
        manager.setContextAttributesMapper(authorizeRequest -> Mono.just(java.util.Collections.singletonMap(
                ServerWebExchange.class.getName(),
                authorizeRequest.getAttribute(ServerWebExchange.class.getName()))));

        log.info("OAuth2 Authorized Client Manager configured with auto-refresh (30s clock skew)");
        return manager;
    }
}