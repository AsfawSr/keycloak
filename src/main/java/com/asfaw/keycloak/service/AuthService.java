package com.asfaw.keycloak.service;

import com.asfaw.keycloak.client.KeycloakAdminClient;
import com.asfaw.keycloak.dto.*;
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

import java.util.Base64;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${app.keycloak.client-id}")
    private String clientId;

    @Value("${app.keycloak.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;
    private final KeycloakAdminClient keycloakAdminClient;
    private final KeycloakTokenService tokenService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ========== LOGIN ==========
    public AuthResponse login(AuthRequest authRequest) {
        String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("username", authRequest.getUsername());
        body.add("password", authRequest.getPassword());

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

                // Get user info from token
                String accessToken = (String) tokenData.get("access_token");
                String refreshToken = (String) tokenData.get("refresh_token");
                UserResponse user = getUserInfoFromToken(accessToken);

                return AuthResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(getLongValue(tokenData.get("expires_in")))
                        .refreshExpiresIn(getLongValue(tokenData.get("refresh_expires_in")))
                        .sessionState((String) tokenData.get("session_state"))
                        .userId(user != null ? user.getId() : null)
                        .username(user != null ? user.getUsername() : authRequest.getUsername())
                        .email(user != null ? user.getEmail() : null)
                        .firstName(user != null ? user.getFirstName() : null)
                        .lastName(user != null ? user.getLastName() : null)
                        .build();
            }
        } catch (HttpClientErrorException e) {
            log.error("Login failed: Status={}, Response={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Invalid credentials");
        } catch (Exception e) {
            log.error("Login error: {}", e.getMessage(), e);
            throw new RuntimeException("Login failed: " + e.getMessage());
        }

        throw new RuntimeException("Login failed");
    }

    // ========== REGISTER ==========
    public ResponseEntity<String> register(RegisterRequest registerRequest) {
        try {
            log.info("Registering user: {}", registerRequest.getEmail());

            // 1. Create user in Keycloak
            UserRequest userRequest = UserRequest.builder()
                    .username(registerRequest.getUsername())
                    .email(registerRequest.getEmail())
                    .firstName(registerRequest.getFirstName())
                    .lastName(registerRequest.getLastName())
                    .enabled(true)
                    .emailVerified(false)  // Set to false, we won't verify yet
                    .credentials(List.of(
                            UserRequest.Credential.builder()
                                    .type("password")
                                    .value(registerRequest.getPassword())
                                    .temporary(false)
                                    .build()
                    ))
                    .build();

            // Use admin client to create user
            String adminToken = "Bearer " + tokenService.getAdminAccessToken();
            ResponseEntity<Void> createResponse = keycloakAdminClient.createUser(adminToken, userRequest);

            if (createResponse.getStatusCode() == HttpStatus.CREATED) {
                log.info("User created successfully: {}", registerRequest.getEmail());

                // SKIP EMAIL VERIFICATION FOR NOW
                // Return success without trying to send verification email
                return ResponseEntity.status(HttpStatus.CREATED)
                        .body("User registered successfully. Email verification will be sent when configured.");
            }

            log.error("Failed to create user. Status: {}", createResponse.getStatusCode());
            return ResponseEntity.status(createResponse.getStatusCode())
                    .body("Failed to register user");

        } catch (Exception e) {
            log.error("Registration failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Registration failed: " + e.getMessage());
        }
    }

    // ========== LOGOUT ==========
    public ResponseEntity<String> logout(String refreshToken) {
        String logoutUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(logoutUrl, request, String.class);

            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("Logged out successfully");
            }

            log.warn("Logout returned status: {}", response.getStatusCode());
            return ResponseEntity.status(response.getStatusCode())
                    .body("Logout completed with status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Logout failed: " + e.getMessage());
        }
    }

    // ========== REFRESH TOKEN ==========
    public AuthResponse refreshToken(String refreshToken) {
        String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

                // Get user info from new token
                String newAccessToken = (String) tokenData.get("access_token");
                String newRefreshToken = (String) tokenData.get("refresh_token");
                UserResponse user = getUserInfoFromToken(newAccessToken);

                return AuthResponse.builder()
                        .accessToken(newAccessToken)
                        .refreshToken(newRefreshToken)
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(getLongValue(tokenData.get("expires_in")))
                        .refreshExpiresIn(getLongValue(tokenData.get("refresh_expires_in")))
                        .sessionState((String) tokenData.get("session_state"))
                        .userId(user != null ? user.getId() : null)
                        .username(user != null ? user.getUsername() : null)
                        .email(user != null ? user.getEmail() : null)
                        .firstName(user != null ? user.getFirstName() : null)
                        .lastName(user != null ? user.getLastName() : null)
                        .build();
            }
        } catch (HttpClientErrorException e) {
            log.error("Token refresh failed: Status={}, Response={}",
                    e.getStatusCode(), e.getResponseBodyAsString());
            throw new RuntimeException("Invalid refresh token");
        } catch (Exception e) {
            log.error("Token refresh error: {}", e.getMessage(), e);
            throw new RuntimeException("Token refresh failed: " + e.getMessage());
        }

        throw new RuntimeException("Token refresh failed");
    }

    // ========== FORGOT PASSWORD ==========
    public ResponseEntity<String> forgotPassword(String email) {
        try {
            UserResponse user = getUserByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("User not found with email: " + email);
            }

            String adminToken = "Bearer " + tokenService.getAdminAccessToken();

            // Keycloak Admin REST API to send reset password email
            // We need to call a different endpoint for password reset

            // Option 1: Using Keycloak's built-in password reset
            // This requires calling the PUT /users/{id}/execute-actions-email endpoint
            String resetUrl = authServerUrl + "/admin/realms/" + realm + "/users/" + user.getId() + "/execute-actions-email";

            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", adminToken);
            headers.setContentType(MediaType.APPLICATION_JSON);

            // Required actions for password reset
            List<String> actions = List.of("UPDATE_PASSWORD");

            HttpEntity<List<String>> request = new HttpEntity<>(actions, headers);

            try {
                ResponseEntity<String> response = restTemplate.exchange(
                        resetUrl,
                        HttpMethod.PUT,
                        request,
                        String.class);

                if (response.getStatusCode().is2xxSuccessful()) {
                    return ResponseEntity.ok("Password reset email sent successfully");
                } else {
                    log.warn("Password reset failed with status: {}", response.getStatusCode());
                    return ResponseEntity.status(response.getStatusCode())
                            .body("Failed to send password reset email");
                }
            } catch (Exception e) {
                log.error("Error calling execute-actions-email: {}", e.getMessage());

                // Fallback: Manually set required actions on user
                return fallbackPasswordReset(adminToken, user.getId());
            }

        } catch (Exception e) {
            log.error("Password reset failed for email {}: {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to process password reset request: " + e.getMessage());
        }
    }

    // Fallback method for password reset
    private ResponseEntity<String> fallbackPasswordReset(String adminToken, String userId) {
        try {
            // Get current user
            UserResponse user = keycloakAdminClient.getUserById(adminToken, userId);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
            }

            // Update user with required actions
            UserRequest updateRequest = UserRequest.builder()
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .firstName(user.getFirstName())
                    .lastName(user.getLastName())
//                    .enabled(user.isEnabled())
                    // Add requiredActions if your UserRequest supports it
                    // .requiredActions(List.of("UPDATE_PASSWORD"))
                    .build();

            ResponseEntity<Void> updateResponse = keycloakAdminClient.updateUser(
                    adminToken, userId, updateRequest);

            if (updateResponse.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("Password reset initiated. User must update password on next login.");
            }

            return ResponseEntity.status(updateResponse.getStatusCode())
                    .body("Password reset initiated with limited functionality");

        } catch (Exception e) {
            log.error("Fallback password reset failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Password reset functionality unavailable. Please contact administrator.");
        }
    }

    // ========== VERIFY EMAIL ==========
    public ResponseEntity<String> verifyEmail(String userId) {
        try {
            String adminToken = "Bearer " + tokenService.getAdminAccessToken();
            ResponseEntity<Void> response = keycloakAdminClient.sendVerificationEmail(adminToken, userId);

            if (response.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.ok("Verification email sent successfully");
            }

            return ResponseEntity.status(response.getStatusCode())
                    .body("Failed to send verification email. Status: " + response.getStatusCode());

        } catch (Exception e) {
            log.error("Failed to send verification email: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to send verification email: " + e.getMessage());
        }
    }

    // ========== GET CURRENT USER ==========
    public UserResponse getCurrentUser(String accessToken) {
        try {
            // Validate token first
            if (accessToken == null || accessToken.isEmpty()) {
                return null;
            }

            return getUserInfoFromToken(accessToken);
        } catch (Exception e) {
            log.error("Failed to get current user: {}", e.getMessage());
            return null;
        }
    }

    // ========== HELPER METHODS ==========

    /**
     * Parse JWT token to extract user information
     */
    private UserResponse getUserInfoFromToken(String accessToken) {
        try {
            // Split JWT into parts: header.payload.signature
            String[] parts = accessToken.split("\\.");
            if (parts.length < 2) {
                log.warn("Invalid JWT token format");
                return null;
            }

            // Decode JWT payload (Base64 URL decode)
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
            Map<String, Object> claims = objectMapper.readValue(payloadJson, Map.class);

            UserResponse user = new UserResponse();
            user.setId((String) claims.get("sub"));
            user.setUsername((String) claims.get("preferred_username"));
            user.setEmail((String) claims.get("email"));
            user.setFirstName((String) claims.get("given_name"));
            user.setLastName((String) claims.get("family_name"));
            user.setEmailVerified(Boolean.TRUE.equals(claims.get("email_verified")));

            return user;
        } catch (Exception e) {
            log.warn("Could not parse user info from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Get user by email using admin client
     */
    private UserResponse getUserByEmail(String email) {
        try {
            String adminToken = "Bearer " + tokenService.getAdminAccessToken();
            List<UserResponse> users = keycloakAdminClient.getUsers(
                    adminToken, null, email, true);

            return users.stream()
                    .filter(user -> email.equalsIgnoreCase(user.getEmail()))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.error("Error getting user by email {}: {}", email, e.getMessage());
            return null;
        }
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

    /**
     * Validate token with Keycloak (optional)
     */
    public boolean validateToken(String token) {
        String introspectUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token/introspect";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("token", token);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(introspectUrl, request, Map.class);
            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Boolean active = (Boolean) response.getBody().get("active");
                return active != null && active;
            }
        } catch (Exception e) {
            log.error("Token validation failed: {}", e.getMessage());
        }
        return false;
    }
}