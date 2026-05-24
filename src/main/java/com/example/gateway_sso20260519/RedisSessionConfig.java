package com.example.gateway_sso20260519;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.session.web.server.session.SpringSessionWebSessionStore;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * SESSION SECURITY CONFIGURATION
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Configures the HTTP-only session cookie — the ONLY credential the browser
 * receives. All OAuth2 tokens remain in Redis, referenced by the session ID.
 *
 * SESSION COOKIE PROPERTIES:
 * ─────────────────────────────
 * ┌──────────────────┬──────────────────────────────────────────────────────┐
 * │ Attribute │ Value & Why │
 * ├──────────────────┼──────────────────────────────────────────────────────┤
 * │ HttpOnly │ true → JavaScript cannot read the cookie. │
 * │ │ XSS attacks cannot steal the session ID. │
 * ├──────────────────┼──────────────────────────────────────────────────────┤
 * │ Secure │ true → Cookie only sent over HTTPS. │
 * │ │ Prevents interception on plain HTTP. │
 * ├──────────────────┼──────────────────────────────────────────────────────┤
 * │ SameSite │ Lax → Cookie sent on same-site requests + GET │
 * │ │ navigations from external sites (links). │
 * │ │ Blocks CSRF from cross-site form POSTs. │
 * │ │ Use "Strict" for maximum security (breaks OAuth │
 * │ │ redirect flow; use "Lax" for OAuth2). │
 * ├──────────────────┼──────────────────────────────────────────────────────┤
 * │ Path │ / → Cookie valid for all paths │
 * ├──────────────────┼──────────────────────────────────────────────────────┤
 * │ Name │ SESSION (Spring's default) │
 * └──────────────────┴──────────────────────────────────────────────────────┘
 *
 * WHY REDIS?
 * ─────────────────
 * 1. Horizontal scaling: multiple gateway instances share session state
 * 2. Persistence: sessions survive gateway restarts
 * 3. TTL: Redis automatically expires sessions (no cleanup job needed)
 * 4. Centralized invalidation: logout can delete the session from Redis
 * across all instances simultaneously
 *
 * SESSION SECURITY MODEL:
 * ─────────────────────────
 * Attack: XSS → reads cookies → steals session
 * Defense: HttpOnly flag → JS cannot read SESSION cookie → XSS cannot steal it
 *
 * Attack: CSRF → forges request with session cookie
 * Defense: SameSite=Lax → cookie not sent on cross-site POSTs → CSRF blocked
 * + CSRF token for double protection on state-changing requests
 *
 * Attack: Network intercept → reads session cookie
 * Defense: Secure flag → cookie only sent on HTTPS → intercept gets nothing
 * ═══════════════════════════════════════════════════════════════════════════
 */
@Slf4j
@Configuration
public class RedisSessionConfig {

    @Value("${app.security.secure-cookie:false}")
    private boolean secureCookie;

    @Value("${app.security.same-site-cookie:Lax}")
    private String sameSiteCookie;

    /**
     * Configures the session cookie with all security attributes.
     *
     * Note: The SESSION cookie is set here. The XSRF-TOKEN cookie
     * is configured separately in SecurityConfig (CSRF protection).
     * They serve different purposes:
     * SESSION cookie → identifies the user's session (HttpOnly, Secure)
     * XSRF-TOKEN cookie → CSRF protection token (readable by JS, Secure)
     */
    @Bean
    public WebSessionIdResolver webSessionIdResolver() {
        CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();

        resolver.setCookieName("SESSION");

        resolver.addCookieInitializer(cookie -> {
            cookie.path("/");
            cookie.httpOnly(true);
            cookie.secure(secureCookie);
            if (!sameSiteCookie.isEmpty()) {
                cookie.sameSite(sameSiteCookie);
            }
        });

        log.info("Session cookie configured: HttpOnly=true, Secure={}, SameSite={}", secureCookie, sameSiteCookie.isEmpty() ? "(none)" : sameSiteCookie);
        return resolver;
    }
}
