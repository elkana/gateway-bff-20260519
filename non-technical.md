# SecurityConfig.java presentation for non-tech

**Session ID:** ses_1a3a78f6cffe019CQDx1jldjbN
**Created:** 5/25/2026, 6:36:00 AM
**Updated:** 5/25/2026, 6:36:18 AM

---

## User

Analyze SecurityConfig.java and help me build a presentation to non-technical users about why some methods needed for some several cases. avoid programming language, draw flow that easy to understand, and use markdown format only.

---

## Assistant (Build · Big Pickle · 2.9s)

_Thinking:_

The user wants me to analyze SecurityConfig.java and help them build a presentation about it for non-technical users. Let me first read the file.

**Tool: read**

**Input:**
```json
{
  "filePath": "/Users/erictarigan/git/security/solution/gateway-sso20260519/src/main/java/com/example/gateway_sso20260519/SecurityConfig.java"
}
```

**Output:**
```
<path>/Users/erictarigan/git/security/solution/gateway-sso20260519/src/main/java/com/example/gateway_sso20260519/SecurityConfig.java</path>
<type>file</type>
<content>
1: package com.example.gateway_sso20260519;
2: 
3: import lombok.RequiredArgsConstructor;
4: import lombok.extern.slf4j.Slf4j;
5: import org.springframework.beans.factory.annotation.Value;
6: import org.springframework.context.annotation.Bean;
7: import org.springframework.context.annotation.Configuration;
8: import org.springframework.http.HttpStatus;
9: import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
10: import org.springframework.security.config.web.server.ServerHttpSecurity;
11: import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
12: import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
13: import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
14: import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
15: import org.springframework.security.web.server.SecurityWebFilterChain;
16: import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
17: import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
18: import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
19: import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
20: import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter;
21: import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
22: import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
23: import org.springframework.web.server.ServerWebExchange;
24: import reactor.core.publisher.Mono;
25: 
26: import java.net.URI;
27: 
28: /**
29:  * ═══════════════════════════════════════════════════════════════════════════
30:  * SECURITY CONFIGURATION — BFF Pattern with OAuth2 + Keycloak
31:  * ═══════════════════════════════════════════════════════════════════════════
32:  *
33:  * WHAT THIS DOES:
34:  * 1. Forces all requests through authentication (except public paths)
35:  * 2. Delegates login to Keycloak via Authorization Code Flow
36:  * 3. Stores tokens server-side (Redis); browser gets only a session cookie
37:  * 4. Enforces role-based access control on each route
38:  * 5. Handles logout (local + Keycloak OIDC backchannel)
39:  * 6. Configures CSRF protection (SPA-compatible)
40:  *
41:  * WHY NOT JWT IN BROWSER?
42:  * ─────────────────────────
43:  * localStorage/sessionStorage are accessible to ANY JavaScript on the page.
44:  * XSS attacks steal stored tokens silently. An HTTP-only cookie cannot be
45:  * read by JavaScript — only the browser sends it, only the server reads it.
46:  * ═══════════════════════════════════════════════════════════════════════════
47:  */
48: @Slf4j
49: @Configuration
50: @EnableWebFluxSecurity
51: @RequiredArgsConstructor
52: public class SecurityConfig {
53: 
54:         private final ReactiveClientRegistrationRepository clientRegistrationRepository;
55: 
56:         @Value("${app.security.post-logout-redirect-uri}")
57:         private String postLogoutRedirectUri;
58: 
59:         @Value("${app.security.base-url}")
60:         private String baseUrl;
61: 
62:         /**
63:          * PUBLIC PATHS — no authentication required.
64:          * Everything else is blocked unless the user has a valid session.
65:          */
66:         private static final String[] PUBLIC_PATHS = {
67:                         "/actuator/health",
68:                         "/actuator/info",
69:                         "/login",
70:                         "/oauth2/**",
71:                         "/login/oauth2/**",
72:                         "/fallback/**",
73:                         "/error"
74:         };
75: 
76:         /**
77:          * Primary security filter chain.
78:          *
79:          * Spring Security processes requests top-to-bottom through this chain.
80:          * Each filter handles one concern: CSRF, headers, auth, authorization, etc.
81:          */
82:         @Bean
83:         public SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
84:                 return http
85:                                 // ── CSRF PROTECTION ───────────────────────────────────────────────
86:                                 // We enable CSRF with a Cookie-based token repository.
87:                                 // This is SPA-compatible: the browser reads the XSRF-TOKEN cookie
88:                                 // (not HTTP-only) and sends it as a header on mutating requests.
89:                                 // This prevents Cross-Site Request Forgery while allowing JS to
90:                                 // retrieve and use the CSRF token.
91:                                 //
92:                                 // Note: If your frontend is purely server-rendered (Thymeleaf),
93:                                 // you can simplify this. For SPA+BFF, CookieServerCsrfTokenRepository
94:                                 // is the recommended modern approach.
95:                                 .csrf(csrf -> csrf
96:                                                 .csrfTokenRepository(cookieCsrfTokenRepository())
97:                                                 .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
98:                                                 // Vaadin handles its own CSRF — skip gateway CSRF for Vaadin requests
99:                                                 .requireCsrfProtectionMatcher(
100:                                                                 new NegatedServerWebExchangeMatcher(
101:                                                                                 ServerWebExchangeMatchers.pathMatchers(
102:                                                                                                 "/vaadin/**"))))
103: 
104:                                 // ── SECURITY HEADERS ─────────────────────────────────────────────
105:                                 // ISO 27001 / OWASP recommended headers for production
106:                                 .headers(h -> h
107:                                                 // Prevent clickjacking attacks
108:                                                 .frameOptions(frame -> frame
109:                                                                 .mode(XFrameOptionsServerHttpHeadersWriter.Mode.DENY))
110:                                                 // Enable browser XSS filter
111:                                                 .xssProtection(xss -> {
112:                                                 })
113:                                                 // Prevent MIME sniffing
114:                                                 .contentTypeOptions(ct -> {
115:                                                 })
116:                                                 // Force HTTPS (1 year, include subdomains)
117:                                                 .hsts(hsts -> hsts
118:                                                                 .maxAge(java.time.Duration.ofDays(365))
119:                                                                 .includeSubdomains(true)
120:                                                                 .preload(true))
121:                                                 // Restrict referrer information
122:                                                 .referrerPolicy(referrer -> referrer.policy(
123:                                                                 org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)))
124: 
125:                                 // ── AUTHORIZATION RULES ───────────────────────────────────────────
126:                                 // Rules are evaluated in order — more specific rules first.
127:                                 .authorizeExchange(auth -> auth
128:                                                 // Public endpoints (no login required)
129:                                                 .pathMatchers(PUBLIC_PATHS).permitAll()
130: 
131:                                                 // ROLE_admin can access everything
132:                                                 .pathMatchers("/api/admin/**").hasRole("admin")
133: 
134:                                                 // ROLE_cashier for cashier routes
135:                                                 // NOTE: Keycloak roles come in as "ROLE_cashier" after our
136:                                                 // GrantedAuthoritiesMapper in KeycloakRoleConverter maps them
137:                                                 .pathMatchers("/api/cashier/**").hasRole("cashier")
138: 
139:                                                 // Products and orders require any authenticated user
140:                                                 .pathMatchers("/api/products/**").authenticated()
141:                                                 .pathMatchers("/api/orders/**").authenticated()
142: 
143:                                                 // Actuator management endpoints require admin role
144:                                                 .pathMatchers("/actuator/**").hasRole("admin")
145: 
146:                                                 // Everything else requires authentication
147:                                                 .anyExchange().authenticated())
148: 
149:                                 // ── OAUTH2 LOGIN ──────────────────────────────────────────────────
150:                                 // Configures the Authorization Code Flow with Keycloak.
151:                                 //
152:                                 // FLOW:
153:                                 // 1. Unauthenticated request → redirects to
154:                                 // /oauth2/authorization/keycloak
155:                                 // 2. Spring Security builds the authorization URL and redirects browser to
156:                                 // Keycloak
157:                                 // 3. User logs in at Keycloak
158:                                 // 4. Keycloak redirects back to /login/oauth2/code/keycloak with an auth code
159:                                 // 5. Gateway exchanges code for tokens (access + refresh + id) via back-channel
160:                                 // 6. Tokens stored in ReactiveOAuth2AuthorizedClientService (Redis-backed)
161:                                 // 7. Browser receives SESSION cookie — that's it, no tokens in browser
162:                                 .oauth2Login(oauth2 -> oauth2
163:                                                 .authorizationRequestResolver(authorizationRequestResolver())
164:                                                 // After successful login, redirect to originally requested URL
165:                                                 .authenticationSuccessHandler(
166:                                                                 redirectServerAuthenticationSuccessHandler())
167:                                                 // On login failure, redirect to error page
168:                                                 .authenticationFailureHandler((webFilterExchange, exception) -> {
169:                                                         log.error("OAuth2 login failed: {}", exception.getMessage());
170:                                                         webFilterExchange.getExchange().getResponse()
171:                                                                         .setStatusCode(HttpStatus.FOUND);
172:                                                         webFilterExchange.getExchange().getResponse().getHeaders()
173:                                                                         .setLocation(URI.create("/login?error=true"));
174:                                                         return webFilterExchange.getExchange().getResponse()
175:                                                                         .setComplete();
176:                                                 }))
177: 
178:                                 // ── LOGOUT ────────────────────────────────────────────────────────
179:                                 // Two-phase logout:
180:                                 // 1. LOCAL: Spring Security invalidates the server-side session
181:                                 // and clears the SESSION cookie from the browser
182:                                 // 2. KEYCLOAK: The user is redirected to Keycloak's logout endpoint
183:                                 // which invalidates the Keycloak SSO session
184:                                 //
185:                                 // This prevents "re-login without password" via SSO after logout.
186:                                 .logout(l -> l
187:                                                 .logoutUrl("/logout")
188:                                                 .logoutSuccessHandler(oidcLogoutSuccessHandler()))
189: 
190:                                 // ── EXCEPTION HANDLING ────────────────────────────────────────────
191:                                 // Unauthenticated requests → redirect to Keycloak login (not 401)
192:                                 // This is the BFF pattern: browser users see a login page, not an error
193:                                 .exceptionHandling(ex -> ex
194:                                                 .authenticationEntryPoint((exchange, e) -> {
195:                                                         // For API requests (AJAX/fetch), return 401 so JS can handle it
196:                                                         if (isApiRequest(exchange)) {
197:                                                                 exchange.getResponse()
198:                                                                                 .setStatusCode(HttpStatus.UNAUTHORIZED);
199:                                                                 return exchange.getResponse().setComplete();
200:                                                         }
201:                                                         // Save original URL in a cookie so we can redirect back after
202:                                                         // login.
203:                                                         // We use a cookie instead of the session because the session
204:                                                         // cookie
205:                                                         // is not set until the /oauth2/authorization/* request.
206:                                                         String requestPath = exchange.getRequest().getURI().getPath();
207:                                                         String query = exchange.getRequest().getURI().getRawQuery();
208:                                                         String redirectTarget = query != null
209:                                                                         ? requestPath + "?" + query
210:                                                                         : requestPath;
211:                                                         exchange.getResponse().getCookies().add("REDIRECT_URL",
212:                                                                         org.springframework.http.ResponseCookie
213:                                                                                         .from("REDIRECT_URL",
214:                                                                                                         redirectTarget)
215:                                                                                         .path("/")
216:                                                                                         .maxAge(java.time.Duration
217:                                                                                                         .ofMinutes(5))
218:                                                                                         .httpOnly(true)
219:                                                                                         .sameSite("Lax")
220:                                                                                         .build());
221:                                                         // For browser navigation, redirect to OAuth2 login
222:                                                         exchange.getResponse().setStatusCode(HttpStatus.FOUND);
223:                                                         exchange.getResponse().getHeaders()
224:                                                                         .setLocation(URI.create(
225:                                                                                         "/oauth2/authorization/keycloak"));
226:                                                         return exchange.getResponse().setComplete();
227:                                                 })
228:                                                 .accessDeniedHandler((exchange, e) -> {
229:                                                         exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
230:                                                         return exchange.getResponse().setComplete();
231:                                                 }))
232:                                 .build();
233:         }
234: 
235:         /**
236:          * CSRF Token Repository (Cookie-based, SPA-compatible)
237:          *
238:          * The XSRF-TOKEN cookie is readable by JavaScript (NOT HTTP-only) so the
239:          * SPA can read it and include it in the X-XSRF-TOKEN request header.
240:          * The SESSION cookie remains HTTP-only and is never readable by JavaScript.
241:          */
242:         private CookieServerCsrfTokenRepository cookieCsrfTokenRepository() {
243:                 CookieServerCsrfTokenRepository repository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
244:                 repository.setCookiePath("/");
245:                 repository.setCookieName("XSRF-TOKEN");
246:                 repository.setHeaderName("X-XSRF-TOKEN");
247:                 return repository;
248:         }
249: 
250:         /**
251:          * OAuth2 Authorization Request Resolver
252:          *
253:          * Customizes the authorization request sent to Keycloak.
254:          * We use the default resolver — customization point for PKCE, login_hint, etc.
255:          *
256:          * PKCE (Proof Key for Code Exchange) can be added here for additional security
257:          * on public clients. For confidential clients (client_secret set), it's
258:          * optional.
259:          */
260:         private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver() {
261:                 return new DefaultServerOAuth2AuthorizationRequestResolver(
262:                                 clientRegistrationRepository,
263:                                 ServerWebExchangeMatchers.pathMatchers("/oauth2/authorization/{registrationId}"));
264:         }
265: 
266:         /**
267:          * OIDC Logout Success Handler
268:          *
269:          * After local logout (session invalidation), this handler redirects the
270:          * browser to Keycloak's logout endpoint:
271:          * https://keycloak/realms/los-realm/protocol/openid-connect/logout
272:          * ?post_logout_redirect_uri=http://localhost:8080/login
273:          * &id_token_hint=<id_token>
274:          *
275:          * Keycloak validates the id_token_hint to confirm the logout request is
276:          * from the correct client, then invalidates the Keycloak SSO session.
277:          */
278:         @Bean
279:         public ServerLogoutSuccessHandler oidcLogoutSuccessHandler() {
280:                 var h = new OidcClientInitiatedServerLogoutSuccessHandler(
281:                                 clientRegistrationRepository);
282:                 h.setPostLogoutRedirectUri(postLogoutRedirectUri);
283:                 return h;
284:         }
285: 
286:         /**
287:          * Authentication Success Handler — redirect to originally requested URL
288:          *
289:          * After a successful OAuth2 login, this handler checks for a REDIRECT_URL
290:          * cookie (set by the authentication entry point before the Keycloak redirect),
291:          * and sends the browser back to that page instead of "/" (which routes to
292:          * the Vaadin app on port 8082). Falls back to the base URL if no cookie
293:          * is present.
294:          */
295:         private ServerAuthenticationSuccessHandler redirectServerAuthenticationSuccessHandler() {
296:                 return (webFilterExchange, authentication) -> {
297:                         ServerWebExchange exchange = webFilterExchange.getExchange();
298:                         String target = baseUrl;
299:                         org.springframework.http.HttpCookie cookie = exchange.getRequest().getCookies()
300:                                         .getFirst("REDIRECT_URL");
301:                         if (cookie != null) {
302:                                 target = baseUrl + cookie.getValue();
303:                         }
304:                         exchange.getResponse().setStatusCode(HttpStatus.FOUND);
305:                         exchange.getResponse().getHeaders()
306:                                         .setLocation(URI.create(target));
307:                         return exchange.getResponse().setComplete();
308:                 };
309:         }
310: 
311:         /**
312:          * Detects AJAX/fetch requests from JavaScript.
313:          * These should receive 401 JSON responses, not HTML login redirects.
314:          */
315:         private boolean isApiRequest(ServerWebExchange exchange) {
316:                 String accept = exchange.getRequest().getHeaders().getFirst("Accept");
317:                 String xRequestedWith = exchange.getRequest().getHeaders().getFirst("X-Requested-With");
318:                 return (accept != null && accept.contains("application/json"))
319:                                 || "XMLHttpRequest".equals(xRequestedWith);
320:         }
321: }

(End of file - total 321 lines)
</content>
```

---

## Assistant (Build · Big Pickle · 14.8s)

_Thinking:_

The user wants a presentation for non-technical users about SecurityConfig.java. They want:
1. Flow diagrams that are easy to understand
2. No programming language jargon
3. Markdown format only
4. Help them understand why some methods are needed

Let me build a clear, visual markdown presentation using Mermaid diagrams and plain English.

# Gateway Security — A Look Under the Hood

## The Big Picture

Your gateway is like a **security guard at the building entrance**. Every visitor (request) must check in — the guard decides:

- ✅ Who can come in
- 🚪 Where they're allowed to go
- 🆔 How they prove who they are
- 🚶 How they leave

---

## The Login Flow (How a User Gets In)

```
  ┌──────────┐        ┌──────────┐        ┌──────────┐
  │  BROWSER │        │ GATEWAY  │        │ KEYCLOAK │
  │ (You)    │        │ (Guard)  │        │ (ID Badge│
  │          │        │          │        │  Office) │
  └────┬─────┘        └────┬─────┘        └────┬─────┘
       │                   │                   │
       │  1. Try to visit  │                   │
       │  /api/products    │                   │
       │──────────────────>│                   │
       │                   │                   │
       │  2. "Who are you?"│                   │
       │  (redirect to     │                   │
       │   login page)     │                   │
       │<──────────────────│                   │
       │                   │                   │
       │  3. Enter         │                   │
       │  username/password│                   │
       │──────────────────────────────────────>│
       │                   │                   │
       │              4. "Here's your           │
       │  id badge, valid │                   │
       │  for this session"│                   │
       │<──────────────────────────────────────│
       │                   │                   │
       │  5. "You're in!"  │                   │
       │  (redirect back   │                   │
       │   to your page)   │                   │
       │<──────────────────│                   │
```

**Why this matters:** Your password is never stored on our server. We hand ID verification to Keycloak (like a security company). Your browser only gets a **session cookie** — like a paper wristband — not your actual keys.

---

## The Logout Flow (How a User Leaves)

```
  ┌──────────┐        ┌──────────┐        ┌──────────┐
  │  BROWSER │        │ GATEWAY  │        │ KEYCLOAK │
  └────┬─────┘        └────┬─────┘        └────┬─────┘
       │                   │                   │
       │  Click "Logout"   │                   │
       │──────────────────>│                   │
       │                   │                   │
       │ 1. Rip wristband  │                   │
       │    (delete local  │                   │
       │     session)      │                   │
       │                   │                   │
       │ 2. Also tell      │                   │
       │    Keycloak:      │                   │
       │    "This person   │                   │
       │    is done"       │                   │
       │──────────────────────────────────────>│
       │                   │                   │
       │ 3. Keycloak says  │                   │
       │    "Confirmed"    │                   │
       │<──────────────────────────────────────│
       │                   │                   │
       │ 4. Go to login    │                   │
       │    page           │                   │
       │<──────────────────│                   │
```

**Why two steps?** If we only delete our local session, Keycloak still thinks you're logged in. Clicking "login" again would let you right back in without a password — defeating the purpose of logging out.

---

## Who Can Go Where (Role Map)

```
                      ┌─────────────────────────┐
                      │     FRONT DOOR          │
                      │  (Public paths anyone   │
                      │   can see)              │
                      │  • /login               │
                      │  • /error               │
                      └──────────┬──────────────┘
                                 │
                      ┌──────────▼──────────────┐
                      │   NEED ID BADGE         │
                      │  (Any authenticated     │
                      │   user)                 │
                      │  • /api/products        │
                      │  • /api/orders          │
                      └──────────┬──────────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
  ┌────────▼────────┐  ┌────────▼────────┐  ┌────────▼────────┐
  │  CASHIER ONLY   │  │   ADMIN ONLY    │  │   ADMIN ONLY    │
  │  /api/cashier/* │  │  /api/admin/*   │  │  /actuator/*    │
  │                 │  │                 │  │  (system info)  │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## CSRF — What Is It and Why Should I Care?

Imagine someone sends you an email with a picture, but hidden inside that picture is a command like "transfer $1000 to account X." If your browser still has its wristband from logging into the bank, the bank thinks *you* sent that command.

**CSRF protection prevents this.** Every time you do something important (submit a form, place an order), the gateway requires a **secret token** that only the real website can give you. The fake picture in the email doesn't have that token.

```
  LEGIT REQUEST                     FAKE REQUEST (CSRF Attack)
  ┌─────────────────┐              ┌─────────────────┐
  │ Your browser     │              │ Attacker's page │
  │ has XSRF-TOKEN   │              │ has NO token    │
  │ cookie ✓         │              │ ✗               │
  └────────┬─────────┘              └────────┬─────────┘
           │                                  │
           │ "Place order"  ✓                │ "Place order"  ✗
           │ + XSRF token                    │ (no token)
           │                                  │
  ┌────────▼─────────┐              ┌────────▼─────────┐
  │ GATEWAY          │              │ GATEWAY          │
  │ "Token matches — │              │ "No token —      │
  │  order placed!"  │              │  REJECTED!"      │
  └──────────────────┘              └──────────────────┘
```

---

## What Each Method Does (Non-Techie Summary)

| Method Named | What It Does | Why It Exists |
|---|---|---|
| **Security Filter Chain** | The main rulebook at the front door | All security rules live here — without it, the door is wide open |
| **CSRF Token Repository** | Stores the secret handshake token in a browser cookie | Prevents fake websites from sneaking commands through (see above) |
| **Authorization Request Resolver** | Tells the browser where to go for Keycloak login | Routes you to the correct login page |
| **OIDC Logout Success Handler** | Calls Keycloak after local logout to kill the SSO session | Prevents "free re-entry" after you log out |
| **Authentication Success Handler** | Remembers which page you were trying to visit before login | After login, you end up where you wanted to go, not the homepage |
| **API Request Detector** | Sniffs whether the request is from a human or JavaScript | Humans get a login page; apps get a clean 401 error to handle themselves |
| **Exception Handlers** | Catches errors when someone sneaks in a broken session | Redirects to login instead of showing a scary error screen |

---

## One-Sentence Takeaway

> The gateway is a guard that **never stores your password**, uses **Keycloak as the ID-badge office**, hands the browser a **wristband (session cookie)**, knows **who is allowed where**, and rejects **fake commands** hidden inside other websites.

---

