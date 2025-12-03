package com.asfaw.keycloak.service;

import com.asfaw.keycloak.client.KeycloakAdminClient;
import com.asfaw.keycloak.dto.PasswordRequest;
import com.asfaw.keycloak.dto.UserRequest;
import com.asfaw.keycloak.dto.UserResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserManagementService {

    private final KeycloakAdminClient keycloakAdminClient;
    private final KeycloakTokenService tokenService;

    public List<UserResponse> getAllUsers() {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            return keycloakAdminClient.getUsers(token, null, null, true);
        } catch (Exception e) {
            log.error("Error fetching users: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to fetch users: " + e.getMessage(), e);
        }
    }

    public UserResponse getUserByEmail(String email) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            List<UserResponse> users = keycloakAdminClient.getUsers(token, null, email, true);
            return users.stream()
                    .filter(user -> email.equalsIgnoreCase(user.getEmail()))
                    .findFirst()
                    .orElse(null);
        } catch (Exception e) {
            log.error("Error fetching user by email {}: {}", email, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch user: " + e.getMessage(), e);
        }
    }

    public UserResponse getUserById(String userId) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            return keycloakAdminClient.getUserById(token, userId);
        } catch (Exception e) {
            log.error("Error fetching user by ID {}: {}", userId, e.getMessage(), e);
            throw new RuntimeException("Failed to fetch user: " + e.getMessage(), e);
        }
    }

    public ResponseEntity<String> createUser(UserRequest userRequest) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            ResponseEntity<Void> response = keycloakAdminClient.createUser(token, userRequest);

            if (response.getStatusCode() == HttpStatus.CREATED) {
                return ResponseEntity.status(HttpStatus.CREATED).body("User created successfully");
            }
            return ResponseEntity.status(response.getStatusCode())
                    .body("Failed to create user. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error creating user: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error creating user: " + e.getMessage());
        }
    }

    public ResponseEntity<String> updateUser(String userId, UserRequest userRequest) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            ResponseEntity<Void> response = keycloakAdminClient.updateUser(token, userId, userRequest);

            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("User updated successfully");
            }
            return ResponseEntity.status(response.getStatusCode())
                    .body("Failed to update user. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error updating user {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error updating user: " + e.getMessage());
        }
    }

    public ResponseEntity<String> deleteUser(String userId) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            ResponseEntity<Void> response = keycloakAdminClient.deleteUser(token, userId);

            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("User deleted successfully");
            }
            return ResponseEntity.status(response.getStatusCode())
                    .body("Failed to delete user. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error deleting user {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error deleting user: " + e.getMessage());
        }
    }

    public ResponseEntity<String> resetPassword(String userId, String newPassword) {
        try {
            String token = "Bearer " + tokenService.getAdminAccessToken();
            PasswordRequest passwordRequest = new PasswordRequest();
            passwordRequest.setValue(newPassword);
            passwordRequest.setTemporary(false);

            ResponseEntity<Void> response = keycloakAdminClient.resetPassword(token, userId, passwordRequest);

            if (response.getStatusCode() == HttpStatus.NO_CONTENT) {
                return ResponseEntity.ok("Password reset successfully");
            }
            return ResponseEntity.status(response.getStatusCode())
                    .body("Failed to reset password. Status: " + response.getStatusCode());
        } catch (Exception e) {
            log.error("Error resetting password for user {}: {}", userId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error resetting password: " + e.getMessage());
        }
    }
}