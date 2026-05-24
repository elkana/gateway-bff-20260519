package com.example.gateway_sso20260519;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * SECURITY CONFIGURATION — BFF Pattern with OAuth2 + Keycloak
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * WHAT THIS DOES:
 * 1. Forces all requests through authentication (except public paths)
 * 2. Delegates login to Keycloak via Authorization Code Flow
 * 3. Stores tokens server-side (Redis); browser gets only a session cookie
 * 4. Enforces role-based access control on each route
 * 5. Handles logout (local + Keycloak OIDC backchannel)
 * 6. Configures CSRF protection (SPA-compatible)
 *
 * WHY NOT JWT IN BROWSER?
 * ─────────────────────────
 * localStorage/sessionStorage are accessible to ANY JavaScript on the page.
 * XSS attacks steal stored tokens silently. An HTTP-only cookie cannot be
 * read by JavaScript — only the browser sends it, only the server reads it.
 * ═══════════════════════════════════════════════════════════════════════════
 */
@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final ReactiveClientRegistrationRepository clientRegistrationRepository;

        @Value("${app.security.post-logout-redirect-uri}")
        private String postLogoutRedirectUri;

        @Value("${app.security.base-url}")
        private String baseUrl;

        /**
         * PUBLIC PATHS — no authentication required.
         * Everything else is blocked unless the user has a valid session.
         */
        private static final String[] PUBLIC_PATHS = {
                        "/actuator/health",
                        "/actuator/info",
                        "/login",
                        "/oauth2/**",
                        "/login/oauth2/**",
                        "/fallback/**",
                        "/error"
        };

        /**
         * Primary security filter chain.
         *
         * Spring Security processes requests top-to-bottom through this chain.
         * Each filter handles one concern: CSRF, headers, auth, authorization, etc.
         */
        @Bean
        public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
                return http
                                // ── CSRF PROTECTION ───────────────────────────────────────────────
                                // We enable CSRF with a Cookie-based token repository.
                                // This is SPA-compatible: the browser reads the XSRF-TOKEN cookie
                                // (not HTTP-only) and sends it as a header on mutating requests.
                                // This prevents Cross-Site Request Forgery while allowing JS to
                                // retrieve and use the CSRF token.
                                //
                                // Note: If your frontend is purely server-rendered (Thymeleaf),
                                // you can simplify this. For SPA+BFF, CookieServerCsrfTokenRepository
                                // is the recommended modern approach.
                                .csrf(csrf -> csrf
                                                .csrfTokenRepository(cookieCsrfTokenRepository())
                                                .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                                                // Vaadin handles its own CSRF — skip gateway CSRF for Vaadin requests
                                                .requireCsrfProtectionMatcher(
                                                                new NegatedServerWebExchangeMatcher(
                                                                                ServerWebExchangeMatchers.pathMatchers(
                                                                                                "/vaadin/**"))))

                                // ── SECURITY HEADERS ─────────────────────────────────────────────
                                // ISO 27001 / OWASP recommended headers for production
                                .headers(h -> h
                                                // Prevent clickjacking attacks
                                                .frameOptions(frame -> frame
                                                                .mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
                                                // Enable browser XSS filter
                                                .xssProtection(xss -> {
                                                })
                                                // Prevent MIME sniffing
                                                .contentTypeOptions(ct -> {
                                                })
                                                // Force HTTPS (1 year, include subdomains)
                                                .hsts(hsts -> hsts
                                                                .maxAge(java.time.Duration.ofDays(365))
                                                                .includeSubdomains(true)
                                                                .preload(true))
                                                // Restrict referrer information
                                                .referrerPolicy(referrer -> referrer.policy(
                                                                org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))

                                // ── AUTHORIZATION RULES ───────────────────────────────────────────
                                // Rules are evaluated in order — more specific rules first.
                                .authorizeExchange(auth -> auth
                                                // Public endpoints (no login required)
                                                .pathMatchers(PUBLIC_PATHS).permitAll()

                                                // ROLE_admin can access everything
                                                .pathMatchers("/api/admin/**").hasRole("admin")

                                                // ROLE_cashier for cashier routes
                                                // NOTE: Keycloak roles come in as "ROLE_cashier" after our
                                                // GrantedAuthoritiesMapper in KeycloakRoleConverter maps them
                                                .pathMatchers("/api/cashier/**").hasRole("cashier")

                                                // Products and orders require any authenticated user
                                                .pathMatchers("/api/products/**").authenticated()
                                                .pathMatchers("/api/orders/**").authenticated()

                                                // Actuator management endpoints require admin role
                                                .pathMatchers("/actuator/**").hasRole("admin")

                                                // Everything else requires authentication
                                                .anyExchange().authenticated())

                                // ── OAUTH2 LOGIN ──────────────────────────────────────────────────
                                // Configures the Authorization Code Flow with Keycloak.
                                //
                                // FLOW:
                                // 1. Unauthenticated request → redirects to
                                // /oauth2/authorization/keycloak
                                // 2. Spring Security builds the authorization URL and redirects browser to
                                // Keycloak
                                // 3. User logs in at Keycloak
                                // 4. Keycloak redirects back to /login/oauth2/code/keycloak with an auth code
                                // 5. Gateway exchanges code for tokens (access + refresh + id) via back-channel
                                // 6. Tokens stored in ReactiveOAuth2AuthorizedClientService (Redis-backed)
                                // 7. Browser receives SESSION cookie — that's it, no tokens in browser
                                .oauth2Login(oauth2 -> oauth2
                                                .authorizationRequestResolver(authorizationRequestResolver())
                                                // After successful login, redirect to originally requested URL
                                                .authenticationSuccessHandler(
                                                                redirectServerAuthenticationSuccessHandler())
                                                // On login failure, redirect to error page
                                                .authenticationFailureHandler((webFilterExchange, exception) -> {
                                                        log.error("OAuth2 login failed: {}", exception.getMessage());
                                                        webFilterExchange.getExchange().getResponse()
                                                                        .setStatusCode(HttpStatus.FOUND);
                                                        webFilterExchange.getExchange().getResponse().getHeaders()
                                                                        .setLocation(URI.create("/login?error=true"));
                                                        return webFilterExchange.getExchange().getResponse()
                                                                        .setComplete();
                                                }))

                                // ── LOGOUT ────────────────────────────────────────────────────────
                                // Two-phase logout:
                                // 1. LOCAL: Spring Security invalidates the server-side session
                                // and clears the SESSION cookie from the browser
                                // 2. KEYCLOAK: The user is redirected to Keycloak's logout endpoint
                                // which invalidates the Keycloak SSO session
                                //
                                // This prevents "re-login without password" via SSO after logout.
                                .logout(l -> l
                                                .logoutUrl("/logout")
                                                .logoutSuccessHandler(oidcLogoutSuccessHandler()))

                                // ── EXCEPTION HANDLING ────────────────────────────────────────────
                                // Unauthenticated requests → redirect to Keycloak login (not 401)
                                // This is the BFF pattern: browser users see a login page, not an error
                                .exceptionHandling(ex -> ex
                                                .authenticationEntryPoint((exchange, e) -> {
                                                        // For API requests (AJAX/fetch), return 401 so JS can handle it
                                                        if (isApiRequest(exchange)) {
                                                                exchange.getResponse()
                                                                                .setStatusCode(HttpStatus.UNAUTHORIZED);
                                                                return exchange.getResponse().setComplete();
                                                        }
                                                        // Save original URL in a cookie so we can redirect back after
                                                        // login.
                                                        // We use a cookie instead of the session because the session
                                                        // cookie
                                                        // is not set until the /oauth2/authorization/* request.
                                                        String requestPath = exchange.getRequest().getURI().getPath();
                                                        String query = exchange.getRequest().getURI().getRawQuery();
                                                        String redirectTarget = query != null
                                                                        ? requestPath + "?" + query
                                                                        : requestPath;
                                                        exchange.getResponse().getCookies().add("REDIRECT_URL",
                                                                        org.springframework.http.ResponseCookie
                                                                                        .from("REDIRECT_URL",
                                                                                                        redirectTarget)
                                                                                        .path("/")
                                                                                        .maxAge(java.time.Duration
                                                                                                        .ofMinutes(5))
                                                                                        .httpOnly(true)
                                                                                        .sameSite("Lax")
                                                                                        .build());
                                                        // For browser navigation, redirect to OAuth2 login
                                                        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                                                        exchange.getResponse().getHeaders()
                                                                        .setLocation(URI.create(
                                                                                        "/oauth2/authorization/keycloak"));
                                                        return exchange.getResponse().setComplete();
                                                })
                                                .accessDeniedHandler((exchange, e) -> {
                                                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                                        return exchange.getResponse().setComplete();
                                                }))
                                .build();
        }

        /**
         * CSRF Token Repository (Cookie-based, SPA-compatible)
         *
         * The XSRF-TOKEN cookie is readable by JavaScript (NOT HTTP-only) so the
         * SPA can read it and include it in the X-XSRF-TOKEN request header.
         * The SESSION cookie remains HTTP-only and is never readable by JavaScript.
         */
        private CookieServerCsrfTokenRepository cookieCsrfTokenRepository() {
                CookieServerCsrfTokenRepository repository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
                repository.setCookiePath("/");
                repository.setCookieName("XSRF-TOKEN");
                repository.setHeaderName("X-XSRF-TOKEN");
                return repository;
        }

        /**
         * OAuth2 Authorization Request Resolver
         *
         * Customizes the authorization request sent to Keycloak.
         * We use the default resolver — customization point for PKCE, login_hint, etc.
         *
         * PKCE (Proof Key for Code Exchange) can be added here for additional security
         * on public clients. For confidential clients (client_secret set), it's
         * optional.
         */
        private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver() {
                return new DefaultServerOAuth2AuthorizationRequestResolver(
                                clientRegistrationRepository,
                                ServerWebExchangeMatchers.pathMatchers("/oauth2/authorization/{registrationId}"));
        }

        /**
         * OIDC Logout Success Handler
         *
         * After local logout (session invalidation), this handler redirects the
         * browser to Keycloak's logout endpoint:
         * https://keycloak/realms/los-realm/protocol/openid-connect/logout
         * ?post_logout_redirect_uri=http://localhost:8080/login
         * &id_token_hint=<id_token>
         *
         * Keycloak validates the id_token_hint to confirm the logout request is
         * from the correct client, then invalidates the Keycloak SSO session.
         */
        @Bean
        public ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
                var h = new OidcClientInitiatedServerLogoutSuccessHandler(
                                clientRegistrationRepository);
                h.setPostLogoutRedirectUri(postLogoutRedirectUri);
                return h;
        }

        /**
         * Authentication Success Handler — redirect to originally requested URL
         *
         * After a successful OAuth2 login, this handler checks for a REDIRECT_URL
         * cookie (set by the authentication entry point before the Keycloak redirect),
         * and sends the browser back to that page instead of "/" (which routes to
         * the Vaadin app on port 8082). Falls back to the base URL if no cookie
         * is present.
         */
        private ServerAuthenticationSuccessHandler redirectServerAuthenticationSuccessHandler() {
                return (webFilterExchange, authentication) -> {
                        ServerWebExchange exchange = webFilterExchange.getExchange();
                        String target = baseUrl;
                        org.springframework.http.HttpCookie cookie = exchange.getRequest().getCookies()
                                        .getFirst("REDIRECT_URL");
                        if (cookie != null) {
                                target = baseUrl + cookie.getValue();
                        }
                        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
                        exchange.getResponse().getHeaders()
                                        .setLocation(URI.create(target));
                        return exchange.getResponse().setComplete();
                };
        }

        /**
         * Detects AJAX/fetch requests from JavaScript.
         * These should receive 401 JSON responses, not HTML login redirects.
         */
        private boolean isApiRequest(ServerWebExchange exchange) {
                String accept = exchange.getRequest().getHeaders().getFirst("Accept");
                String xRequestedWith = exchange.getRequest().getHeaders().getFirst("X-Requested-With");
                return (accept != null && accept.contains("application/json"))
                                || "XMLHttpRequest".equals(xRequestedWith);
        }
}