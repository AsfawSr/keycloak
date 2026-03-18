package com.asfaw.keycloak.service;

import com.asfaw.keycloak.config.ServiceScopeProperties;
import com.asfaw.keycloak.dto.TokenDownscopeRequest;
import com.asfaw.keycloak.dto.TokenDownscopeResponse;
import com.asfaw.keycloak.util.TokenUtils;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenDownscopingService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${app.keycloak.client-id}")
    private String clientId;

    @Value("${app.keycloak.client-secret}")
    private String clientSecret;

    @Value("${app.keycloak.downscope.max-expiration:7200}")
    private int maxExpiration;

    @Value("${app.keycloak.downscope.default-expiration:3600}")
    private int defaultExpiration;

    private final RestTemplate restTemplate;
    private final ServiceScopeProperties serviceScopeProperties;

    /**
     * Creates a downscoped token for a specific microservice.
     * Rate-limited to prevent Keycloak from being hammered.
     */
    @RateLimiter(name = "downscopeToken")
    public TokenDownscopeResponse downscopeToken(TokenDownscopeRequest request) {
        log.info("Downscoping token for service: {}", request.getTargetService());

        if (!validateOriginalToken(request.getOriginalToken())) {
            throw new RuntimeException("Invalid or expired original token");
        }

        List<String> targetScopes = determineTargetScopes(request);
        List<String> targetRoles = determineTargetRoles(request);

        TokenDownscopeResponse response = performTokenExchange(request, targetScopes, targetRoles);
        log.info("Successfully downscoped token for service: {}", request.getTargetService());
        return response;
    }

    /**
     * Validates a token via Keycloak introspection.
     */
    public boolean validateOriginalToken(String token) {
        try {
            String introspectUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token/introspect";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("token", token);

            ResponseEntity<Map> response = restTemplate.postForEntity(
                    introspectUrl, new HttpEntity<>(body, headers), Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Boolean active = (Boolean) response.getBody().get("active");
                return Boolean.TRUE.equals(active);
            }
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Revokes a token via Keycloak's revocation endpoint.
     */
    public void revokeToken(String token) {
        String revokeUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/revoke";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("token", token);

        try {
            restTemplate.postForEntity(revokeUrl, new HttpEntity<>(body, headers), Void.class);
            log.info("Token revoked successfully");
        } catch (Exception e) {
            log.error("Token revocation failed: {}", e.getMessage());
            throw new RuntimeException("Token revocation failed: " + e.getMessage(), e);
        }
    }

    public List<String> getServiceScopes(String serviceName) {
        return serviceScopeProperties.getScopes().getOrDefault(serviceName, Collections.emptyList());
    }

    public List<String> getServiceRoles(String serviceName) {
        return serviceScopeProperties.getRoles().getOrDefault(serviceName, Collections.emptyList());
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /**
     * Validates requested scopes against the allowed list for the target service.
     * Falls back to all predefined scopes only when none are explicitly requested.
     * Throws if no valid service scopes remain after filtering.
     */
    private List<String> determineTargetScopes(TokenDownscopeRequest request) {
        List<String> allowedScopes = serviceScopeProperties.getScopes()
                .getOrDefault(request.getTargetService(), Collections.emptyList());

        List<String> scopes = new ArrayList<>();

        if (request.getRequiredScopes() != null && !request.getRequiredScopes().isEmpty()) {
            for (String scope : request.getRequiredScopes()) {
                if (allowedScopes.contains(scope)) {
                    scopes.add(scope);
                } else {
                    log.warn("Scope '{}' not allowed for service '{}', skipping", scope, request.getTargetService());
                }
            }
            if (scopes.isEmpty()) {
                throw new RuntimeException(
                        "None of the requested scopes are permitted for service: " + request.getTargetService());
            }
        } else {
            scopes.addAll(allowedScopes);
        }

        scopes.addAll(List.of("openid", "profile", "email"));
        return scopes.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Validates requested roles against the allowed list for the target service.
     * Falls back to all predefined roles only when none are explicitly requested.
     */
    private List<String> determineTargetRoles(TokenDownscopeRequest request) {
        List<String> allowedRoles = serviceScopeProperties.getRoles()
                .getOrDefault(request.getTargetService(), Collections.emptyList());

        List<String> roles = new ArrayList<>();

        if (request.getRequiredRoles() != null && !request.getRequiredRoles().isEmpty()) {
            for (String role : request.getRequiredRoles()) {
                if (allowedRoles.contains(role)) {
                    roles.add(role);
                } else {
                    log.warn("Role '{}' not allowed for service '{}', skipping", role, request.getTargetService());
                }
            }
        } else {
            roles.addAll(allowedRoles);
        }

        return roles.stream().distinct().collect(Collectors.toList());
    }

    private TokenDownscopeResponse performTokenExchange(TokenDownscopeRequest request,
                                                        List<String> scopes, List<String> roles) {
        String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("subject_token", request.getOriginalToken());
        body.add("requested_token_type", "urn:ietf:params:oauth:token-type:jwt");
        body.add("scope", String.join(" ", scopes));
        body.add("audience", request.getAudience() != null ? request.getAudience() : request.getTargetService());

        int expiry = defaultExpiration;
        if (request.getExpiresIn() != null) {
            expiry = Math.min(request.getExpiresIn(), maxExpiration);
            if (request.getExpiresIn() > maxExpiration) {
                log.warn("Requested expiration {}s exceeds max {}s, capping", request.getExpiresIn(), maxExpiration);
            }
        }
        body.add("requested_expiration", String.valueOf(expiry));

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(
                    tokenUrl, new HttpEntity<>(body, headers), Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();
                return TokenDownscopeResponse.builder()
                        .downscopedToken((String) tokenData.get("access_token"))
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(TokenUtils.toLong(tokenData.get("expires_in")))
                        .grantedScopes(scopes)
                        .grantedRoles(roles)
                        .audience(request.getAudience() != null ? request.getAudience() : request.getTargetService())
                        .targetService(request.getTargetService())
                        .issuedAt(Instant.now().toString())
                        .build();
            }

            throw new RuntimeException("Token exchange failed with status: " + response.getStatusCode());

        } catch (HttpClientErrorException e) {
            log.error("Token exchange failed: status={}, body={}", e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Token exchange failed: " + e.getResponseBodyAsString());
        }
    }
}
