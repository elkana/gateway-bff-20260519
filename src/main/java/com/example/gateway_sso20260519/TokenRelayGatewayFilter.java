package com.example.gateway_sso20260519;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * TOKEN RELAY GATEWAY FILTER
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * This global filter intercepts ALL requests passing through the gateway and:
 *
 * 1. Extracts the OAuth2AuthenticationToken from the security context
 * (which comes from the server-side session in Redis)
 *
 * 2. Calls the ReactiveOAuth2AuthorizedClientManager to get a valid token.
 * The manager automatically refreshes expired tokens if a refresh_token
 * is available. This is completely transparent to the frontend.
 *
 * 3. Injects "Authorization: Bearer <access_token>" into the downstream
 * request headers before forwarding to the microservice.
 *
 * This complements Spring Cloud Gateway's built-in TokenRelay= filter.
 * Use this custom filter when you need finer control over the token relay
 * process, such as logging, error handling, or token transformation.
 *
 * HOW AUTO-REFRESH WORKS:
 * ─────────────────────────
 * Request comes in → access token expired?
 * YES → call Keycloak /token with refresh_token (server-to-server)
 * → get new access_token + refresh_token
 * → save to Redis session
 * → inject new access_token in downstream request
 * NO → inject existing access_token in downstream request
 *
 * The frontend NEVER KNOWS the token was refreshed. It just gets its
 * response as if nothing happened.
 * ═══════════════════════════════════════════════════════════════════════════
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenRelayGatewayFilter implements GlobalFilter, Ordered {

    private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

    /**
     * Run after Spring Security filters (which are at Integer.MIN_VALUE)
     * but before the routing filter (which is at Integer.MIN_VALUE + 1).
     * Order 0 is a safe middle ground.
     */
    @Override
    public int getOrder() {
        return -1; // Before routing, after security
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(securityContext -> {
                    var authentication = securityContext.getAuthentication();

                    // Only process OAuth2 authenticated users
                    if (!(authentication instanceof OAuth2AuthenticationToken oauth2Token)) {
                        log.debug("No OAuth2 authentication found, passing through");
                        return chain.filter(exchange);
                    }

                    String clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
                    String principalName = oauth2Token.getName();

                    // Build the authorization request
                    // The manager will check token expiry and refresh if needed
                    OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                            .withClientRegistrationId(clientRegistrationId)
                            .principal(oauth2Token)
                            .attribute(ServerWebExchange.class.getName(), exchange)
                            .build();

                    return authorizedClientManager.authorize(authorizeRequest)
                            .flatMap(authorizedClient -> {
                                String accessToken = authorizedClient.getAccessToken().getTokenValue();

                                log.debug("Relaying Bearer token for user '{}' to: {}",
                                        principalName,
                                        exchange.getRequest().getPath());

                                // Mutate the request to add the Authorization header
                                // The original cookie headers are NOT forwarded to downstream
                                // (removed by RemoveRequestHeader=Cookie filter in routes config)
                                ServerWebExchange mutatedExchange = exchange.mutate()
                                        .request(r -> r
                                                .headers(h -> {
                                                    h.set(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
                                                    // Add user info headers for convenience
                                                    h.set("X-User-Id", principalName);
                                                    h.set("X-Client-Id", clientRegistrationId);
                                                }))
                                        .build();

                                return chain.filter(mutatedExchange);
                            })
                            .onErrorResume(e -> {
                                log.error("Token relay/refresh failed for user '{}': {}",
                                        principalName, e.getMessage());
                                // If token refresh fails (e.g., refresh token expired),
                                // redirect to login instead of returning 500
                                exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                                exchange.getResponse().getHeaders()
                                        .setLocation(java.net.URI.create("/oauth2/authorization/keycloak"));
                                return exchange.getResponse().setComplete();
                            });
                })
                // If no security context (unauthenticated request to public path), pass through
                .switchIfEmpty(chain.filter(exchange));
    }
}