package com.asfaw.keycloak.service;

import com.asfaw.keycloak.client.KeycloakAdminClient;
import com.asfaw.keycloak.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    private final RestTemplate restTemplate = new RestTemplate();
    private final KeycloakAdminClient keycloakAdminClient;
    private final KeycloakTokenService tokenService;

    // ========== LOGIN ==========
    public AuthResponse login(AuthRequest authRequest) {
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

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
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

                // Get user info
                UserResponse user = getUserInfo((String) tokenData.get("access_token"));

                return AuthResponse.builder()
                        .accessToken((String) tokenData.get("access_token"))
                        .refreshToken((String) tokenData.get("refresh_token"))
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(((Number) tokenData.get("expires_in")).longValue())
                        .refreshExpiresIn(((Number) tokenData.get("refresh_expires_in")).longValue())
                        .sessionState((String) tokenData.get("session_state"))
                        .userId(user != null ? user.getId() : null)
                        .username(user != null ? user.getUsername() : authRequest.getUsername())
                        .email(user != null ? user.getEmail() : null)
                        .firstName(user != null ? user.getFirstName() : null)
                        .lastName(user != null ? user.getLastName() : null)
                        .build();
            }
        } catch (HttpClientErrorException e) {
            log.error("Login failed for user {}: {}", authRequest.getUsername(), e.getResponseBodyAsString());
            throw new RuntimeException("Invalid username or password");
        }

        throw new RuntimeException("Login failed");
    }

    // ========== REGISTER ==========
    public ResponseEntity<String> register(RegisterRequest registerRequest) {
        try {
            // 1. Create user in Keycloak
            UserRequest userRequest = UserRequest.builder()
                    .username(registerRequest.getUsername())
                    .email(registerRequest.getEmail())
                    .firstName(registerRequest.getFirstName())
                    .lastName(registerRequest.getLastName())
                    .enabled(true)
                    .emailVerified(false)
                    .credentials(java.util.List.of(
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
                // 2. Get the created user to get ID
                UserResponse createdUser = getUserByEmail(registerRequest.getEmail());

                if (createdUser != null) {
                    // 3. Assign default USER role (optional - depends on your setup)
                    // 4. Send verification email
                    keycloakAdminClient.sendVerificationEmail(adminToken, createdUser.getId());

                    return ResponseEntity.status(HttpStatus.CREATED)
                            .body("User registered successfully. Verification email sent.");
                }
            }

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
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/logout";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(url, request, String.class);

            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("Logged out successfully");
            }

            return ResponseEntity.status(response.getStatusCode()).body("Logout failed");
        } catch (Exception e) {
            log.error("Logout failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Logout failed: " + e.getMessage());
        }
    }

    // ========== REFRESH TOKEN ==========
    public AuthResponse refreshToken(String refreshToken) {
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(url, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> tokenData = response.getBody();

                return AuthResponse.builder()
                        .accessToken((String) tokenData.get("access_token"))
                        .refreshToken((String) tokenData.get("refresh_token"))
                        .tokenType((String) tokenData.get("token_type"))
                        .expiresIn(((Number) tokenData.get("expires_in")).longValue())
                        .refreshExpiresIn(((Number) tokenData.get("refresh_expires_in")).longValue())
                        .sessionState((String) tokenData.get("session_state"))
                        .build();
            }
        } catch (Exception e) {
            log.error("Token refresh failed: {}", e.getMessage());
            throw new RuntimeException("Token refresh failed");
        }

        throw new RuntimeException("Token refresh failed");
    }

    // ========== PASSWORD RESET ==========
    public ResponseEntity<String> forgotPassword(String email) {
        try {
            UserResponse user = getUserByEmail(email);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("User not found with email: " + email);
            }

            String adminToken = "Bearer " + tokenService.getAdminAccessToken();

            // Send password reset email
            keycloakAdminClient.sendVerificationEmail(adminToken, user.getId());

            return ResponseEntity.ok("Password reset email sent successfully");
        } catch (Exception e) {
            log.error("Password reset failed for email {}: {}", email, e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to send password reset email");
        }
    }

    // ========== HELPER METHODS ==========
    private UserResponse getUserInfo(String accessToken) {
        String url = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/userinfo";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<Void> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<Map> response = restTemplate.exchange(
                    url, HttpMethod.GET, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map<String, Object> userInfo = response.getBody();

                UserResponse user = new UserResponse();
                user.setId((String) userInfo.get("sub"));
                user.setUsername((String) userInfo.get("preferred_username"));
                user.setEmail((String) userInfo.get("email"));
                user.setFirstName((String) userInfo.get("given_name"));
                user.setLastName((String) userInfo.get("family_name"));

                return user;
            }
        } catch (Exception e) {
            log.error("Failed to get user info: {}", e.getMessage());
        }

        return null;
    }

    private UserResponse getUserByEmail(String email) {
        try {
            String adminToken = "Bearer " + tokenService.getAdminAccessToken();
            java.util.List<UserResponse> users = keycloakAdminClient.getUsers(
                    adminToken, null, email, true);

            return users.stream()
                    .filter(user -> email.equalsIgnoreCase(user.getEmail()))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.error("Error getting user by email: {}", e.getMessage());
            return null;
        }
    }

    // ========== VERIFY EMAIL ==========
    public ResponseEntity<String> verifyEmail(String userId) {
        try {
            String adminToken = "Bearer " + tokenService.getAdminAccessToken();
            keycloakAdminClient.sendVerificationEmail(adminToken, userId);

            return ResponseEntity.ok("Verification email sent successfully");
        } catch (Exception e) {
            log.error("Failed to send verification email: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to send verification email");
        }
    }

    // ========== GET CURRENT USER ==========
    public UserResponse getCurrentUser(String accessToken) {
        return getUserInfo(accessToken);
    }
}
