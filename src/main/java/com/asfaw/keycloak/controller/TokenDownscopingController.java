package com.asfaw.keycloak.controller;

import com.asfaw.keycloak.dto.TokenDownscopeRequest;
import com.asfaw.keycloak.dto.TokenDownscopeResponse;
import com.asfaw.keycloak.service.TokenDownscopingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/tokens")
@RequiredArgsConstructor
@Slf4j
public class TokenDownscopingController {

    private final TokenDownscopingService tokenDownscopingService;

    /**
     * Downscope a token for a specific microservice
     */
    @PostMapping("/downscope")
    public ResponseEntity<TokenDownscopeResponse> downscopeToken(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody TokenDownscopeRequest request) {
        
        // Set the original token from the current authentication
        request.setOriginalToken(jwt.getTokenValue());
        
        try {
            TokenDownscopeResponse response = tokenDownscopingService.downscopeToken(request);
            log.info("Token downscoped successfully for service: {}", request.getTargetService());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            log.error("Token downscoping failed: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Get available scopes for a service
     */
    @GetMapping("/scopes/{serviceName}")
    public ResponseEntity<List<String>> getServiceScopes(@PathVariable String serviceName) {
        List<String> scopes = tokenDownscopingService.getServiceScopes(serviceName);
        return ResponseEntity.ok(scopes);
    }

    /**
     * Get available roles for a service
     */
    @GetMapping("/roles/{serviceName}")
    public ResponseEntity<List<String>> getServiceRoles(@PathVariable String serviceName) {
        List<String> roles = tokenDownscopingService.getServiceRoles(serviceName);
        return ResponseEntity.ok(roles);
    }

    /**
     * Validate a downscoped token via Keycloak introspection
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateDownscopedToken(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Token is required"));
        }

        boolean valid = tokenDownscopingService.validateOriginalToken(token);
        if (valid) {
            return ResponseEntity.ok(Map.of("valid", true));
        } else {
            return ResponseEntity.ok(Map.of("valid", false, "error", "Token is invalid or expired"));
        }
    }

    /**
     * Revoke a downscoped token via Keycloak revocation endpoint
     */
    @PostMapping("/revoke")
    public ResponseEntity<Map<String, String>> revokeDownscopedToken(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Token is required"));
        }

        try {
            tokenDownscopingService.revokeToken(token);
            return ResponseEntity.ok(Map.of("message", "Token revoked successfully"));
        } catch (Exception e) {
            log.error("Token revocation failed: {}", e.getMessage());
            return ResponseEntity.internalServerError().body(Map.of("error", "Token revocation failed"));
        }
    }
}
