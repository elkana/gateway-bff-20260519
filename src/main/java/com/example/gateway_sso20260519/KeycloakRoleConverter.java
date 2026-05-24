package com.example.gateway_sso20260519;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * KEYCLOAK ROLE CONVERTER
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Keycloak embeds roles in the JWT in a non-standard structure.
 * Spring Security doesn't know about this structure by default.
 * This converter extracts roles from:
 *
 * 1. REALM ROLES (global, apply to all clients in the realm):
 * {
 * "realm_access": {
 * "roles": ["cashier", "admin", "user"]
 * }
 * }
 *
 * 2. CLIENT ROLES (specific to cashier-1-client):
 * {
 * "resource_access": {
 * "cashier-1-client": {
 * "roles": ["cashier_manager", "cashier_operator"]
 * }
 * }
 * }
 *
 * All roles are prefixed with "ROLE_" so Spring Security's
 * hasRole("cashier") matches "ROLE_cashier".
 *
 * USAGE in SecurityConfig:
 * .pathMatchers("/api/cashier/**").hasRole("cashier")
 * // matches users with ROLE_cashier in either realm_access or resource_access
 * ═══════════════════════════════════════════════════════════════════════════
 */
@Slf4j
public class KeycloakRoleConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String REALM_ACCESS_CLAIM = "realm_access";
    private static final String RESOURCE_ACCESS_CLAIM = "resource_access";
    private static final String ROLES_KEY = "roles";
    private static final String CLIENT_ID = "cashier-1-client";

    @Override
    public Flux<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        // ── Extract REALM roles ────────────────────────────────────────────
        // realm_access.roles = ["cashier", "offline_access", "uma_authorization"]
        extractRealmRoles(jwt, authorities);

        // ── Extract CLIENT roles ───────────────────────────────────────────
        // resource_access.cashier-1-client.roles = ["cashier_manager"]
        extractClientRoles(jwt, authorities);

        log.debug("Extracted authorities for user '{}': {}",
                jwt.getClaimAsString("preferred_username"), authorities);

        return Flux.fromIterable(authorities);
    }

    @SuppressWarnings("unchecked")
    private void extractRealmRoles(Jwt jwt, Collection<GrantedAuthority> authorities) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap(REALM_ACCESS_CLAIM);
        if (realmAccess == null)
            return;

        List<String> roles = (List<String>) realmAccess.get(ROLES_KEY);
        if (roles == null)
            return;

        roles.stream()
                .filter(role -> !isInternalKeycloakRole(role)) // filter out Keycloak internal roles
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .forEach(authorities::add);
    }

    @SuppressWarnings("unchecked")
    private void extractClientRoles(Jwt jwt, Collection<GrantedAuthority> authorities) {
        Map<String, Object> resourceAccess = jwt.getClaimAsMap(RESOURCE_ACCESS_CLAIM);
        if (resourceAccess == null)
            return;

        Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(CLIENT_ID);
        if (clientAccess == null)
            return;

        List<String> roles = (List<String>) clientAccess.get(ROLES_KEY);
        if (roles == null)
            return;

        roles.stream()
                .map(role -> new SimpleGrantedAuthority(ROLE_PREFIX + role))
                .forEach(authorities::add);
    }

    /**
     * Filters out Keycloak's internal default roles to keep the authority list
     * clean.
     * These roles are added automatically by Keycloak and are not business roles.
     */
    private boolean isInternalKeycloakRole(String role) {
        return role.startsWith("default-roles-")
                || role.equals("offline_access")
                || role.equals("uma_authorization");
    }
}