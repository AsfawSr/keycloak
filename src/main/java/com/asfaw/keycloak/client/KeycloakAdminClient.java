package com.asfaw.keycloak.client;

import com.asfaw.keycloak.dto.PasswordRequest;
import com.asfaw.keycloak.dto.UserRequest;
import com.asfaw.keycloak.dto.UserResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@FeignClient(
        name = "keycloak-admin-client",
        url = "${keycloak.auth-server-url}",
        path = "/admin/realms/${keycloak.realm}"
)
public interface KeycloakAdminClient {

    @GetMapping("/users")
    List<UserResponse> getUsers(
            @RequestHeader("Authorization") String bearerToken,
            @RequestParam(value = "username", required = false) String username,
            @RequestParam(value = "email", required = false) String email,
            @RequestParam(value = "briefRepresentation", defaultValue = "true") Boolean briefRepresentation
    );

    @PostMapping("/users")
    ResponseEntity<Void> createUser(
            @RequestHeader("Authorization") String bearerToken,
            @RequestBody UserRequest userRequest
    );

    @GetMapping("/users/{id}")
    UserResponse getUserById(
            @RequestHeader("Authorization") String bearerToken,
            @PathVariable("id") String id
    );

    @PutMapping("/users/{id}")
    ResponseEntity<Void> updateUser(
            @RequestHeader("Authorization") String bearerToken,
            @PathVariable("id") String id,
            @RequestBody UserRequest userRequest
    );

    @DeleteMapping("/users/{id}")
    ResponseEntity<Void> deleteUser(
            @RequestHeader("Authorization") String bearerToken,
            @PathVariable("id") String id
    );

    @PutMapping("/users/{id}/reset-password")
    ResponseEntity<Void> resetPassword(
            @RequestHeader("Authorization") String bearerToken,
            @PathVariable("id") String id,
            @RequestBody PasswordRequest passwordRequest
    );

    @PutMapping("/users/{id}/send-verify-email")
    ResponseEntity<Void> sendVerificationEmail(
            @RequestHeader("Authorization") String bearerToken,
            @PathVariable("id") String id
    );
}