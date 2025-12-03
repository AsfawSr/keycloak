package com.asfaw.keycloak.controller;


import com.asfaw.keycloak.dto.*;
import com.asfaw.keycloak.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest authRequest) {
        try {
            AuthResponse response = authService.login(authRequest);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        return authService.register(registerRequest);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest logoutRequest,
                                    HttpServletRequest request) {
        // Try to get refresh token from request or body
        String refreshToken = logoutRequest.getRefreshToken();
        if (refreshToken == null) {
            // Try to get from Authorization header
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                refreshToken = authHeader.substring(7);
            }
        }

        if (refreshToken == null) {
            return ResponseEntity.badRequest().body("Refresh token is required");
        }

        return authService.logout(refreshToken);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestParam("refresh_token") String refreshToken) {
        try {
            AuthResponse response = authService.refreshToken(refreshToken);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        return authService.forgotPassword(email);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<?> sendVerificationEmail(@RequestParam String userId) {
        return authService.verifyEmail(userId);
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body("Authorization header is required");
        }

        String token = authHeader.substring(7);
        UserResponse user = authService.getCurrentUser(token);

        if (user == null) {
            return ResponseEntity.status(404).body("User not found");
        }

        return ResponseEntity.ok(user);
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(
            @RequestParam String userId,
            @RequestParam String currentPassword,
            @RequestParam String newPassword) {
        // This would require additional implementation
        // You'd need to verify current password first, then update
        return ResponseEntity.ok("Password change endpoint - implement as needed");
    }
}
