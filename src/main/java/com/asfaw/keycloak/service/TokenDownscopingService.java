package com.asfaw.keycloak.service;

import com.asfaw.keycloak.dto.TokenDownscopeRequest;
import com.asfaw.keycloak.dto.TokenDownscopeResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    // Predefined service scopes configuration
    private static final Map<String, List<String>> SERVICE_SCOPES = Map.of(
        "order-service", List.of("read:orders", "write:orders"),
        "payment-service", List.of("read:payments", "write:payments"),
        "user-service", List.of("read:users", "write:users"),
        "inventory-service", List.of("read:inventory", "write:inventory"),
        "notification-service", List.of("send:notifications")
    );

    // Predefined service roles configuration
    private static final Map<String, List<String>> SERVICE_ROLES = Map.of(
        "order-service", List.of("ORDER_USER", "ORDER_ADMIN"),
        "payment-service", List.of("PAYMENT_USER", "PAYMENT_ADMIN"),
        "user-service", List.of("USER_MANAGER"),
        "admin-service", List.of("ADMIN", "SUPER_ADMIN")
    );

    /**
     * Creates a downscoped token for a specific microservice
     */
    public TokenDownscopeResponse downscopeToken(TokenDownscopeRequest request) {
        try {
            log.info("Downscoping token for service: {}", request.getTargetService());

            // Validate original token
            if (!validateOriginalToken(request.getOriginalToken())) {
                throw new RuntimeException("Invalid or expired original token");
            }

            // Determine scopes and roles for target service
            List<String> targetScopes = determineTargetScopes(request);
            List<String> targetRoles = determineTargetRoles(request);

            // Create downscoped token using Keycloak's token exchange
            TokenDownscopeResponse response = performTokenExchange(request, targetScopes, targetRoles);

            log.info("Successfully downscoped token for service: {}", request.getTargetService());
            return response;

        } catch (Exception e) {
            log.error("Token downscoping failed for service {}: {}", 
                    request.getTargetService(), e.getMessage(), e);
            throw new RuntimeException("Token downscoping failed: " + e.getMessage(), e);
        }
    }

    /**
     * Validates the original token with Keycloak
     */
    private boolean validateOriginalToken(String token) {
        try {
            String introspectUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token/introspect";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("client_id", clientId);
            body.add("client_secret", clientSecret);
            body.add("token", token);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

            ResponseEntity<Map> response = restTemplate.postForEntity(introspectUrl, request, Map.class);
            
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Boolean active = (Boolean) response.getBody().get("active");
                return active != null && active;
            }
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Determines the scopes to include in the downscoped token
     */
    private List<String> determineTargetScopes(TokenDownscopeRequest request) {
        List<String> scopes = new ArrayList<>();

        // Add explicitly requested scopes
        if (request.getRequiredScopes() != null) {
            scopes.addAll(request.getRequiredScopes());
        }

        // Add predefined service scopes
        List<String> serviceScopes = SERVICE_SCOPES.get(request.getTargetService());
        if (serviceScopes != null) {
            scopes.addAll(serviceScopes);
        }

        // Add OpenID Connect scopes
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("email");

        // Remove duplicates and return
        return scopes.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Determines the roles to include in the downscoped token
     */
    private List<String> determineTargetRoles(TokenDownscopeRequest request) {
        List<String> roles = new ArrayList<>();

        // Add explicitly requested roles
        if (request.getRequiredRoles() != null) {
            roles.addAll(request.getRequiredRoles());
        }

        // Add predefined service roles
        List<String> serviceRoles = SERVICE_ROLES.get(request.getTargetService());
        if (serviceRoles != null) {
            roles.addAll(serviceRoles);
        }

        return roles.stream().distinct().collect(Collectors.toList());
    }

    /**
     * Performs token exchange with Keycloak to create downscoped token
     */
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
        
        // Add scopes
        if (!scopes.isEmpty()) {
            body.add("scope", String.join(" ", scopes));
        }

        // Add audience if specified
        if (request.getAudience() != null) {
            body.add("audience", request.getAudience());
        } else {
            // Use service name as default audience
            body.add("audience", request.getTargetService());
        }

        // Add custom expiration if specified
        if (request.getExpiresIn() != null) {
            body.add("requested_expiration", request.getExpiresIn().toString());
        }

        HttpEntity<MultiValueMap<String, String>> exchangeRequest = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, exchangeRequest, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();
                
                return TokenDownscopeResponse.builder()
                        .downscopedToken((String) tokenData.get("access_token"))
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(getLongValue(tokenData.get("expires_in")))
                        .grantedScopes(scopes)
                        .grantedRoles(roles)
                        .audience(request.getAudience() != null ? request.getAudience() : request.getTargetService())
                        .targetService(request.getTargetService())
                        .issuedAt(Instant.now().toString())
                        .build();
            }

            throw new RuntimeException("Token exchange failed with status: " + response.getStatusCode());

        } catch (HttpClientErrorException e) {
            log.error("Token exchange failed: Status={}, Response={}", 
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Token exchange failed: " + e.getResponseBodyAsString());
        }
    }

    /**
     * Get available scopes for a service
     */
    public List<String> getServiceScopes(String serviceName) {
        return SERVICE_SCOPES.getOrDefault(serviceName, Collections.emptyList());
    }

    /**
     * Get available roles for a service
     */
    public List<String> getServiceRoles(String serviceName) {
        return SERVICE_ROLES.getOrDefault(serviceName, Collections.emptyList());
    }

    /**
     * Safely convert Number to Long
     */
    private Long getLongValue(Object number) {
        if (number == null) return null;
        if (number instanceof Number) {
            return ((Number) number).longValue();
        }
        try {
            return Long.parseLong(number.toString());
        } catch (NumberFormatException e) {
            log.warn("Could not convert {} to Long", number);
            return null;
        }
    }
}
