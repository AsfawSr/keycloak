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
     * Validate a downscoped token
     */
    @PostMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateDownscopedToken(
            @RequestBody Map<String, String> request) {
        
        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("valid", false, "error", "Token is required"));
        }

        // This would integrate with your token validation logic
        // For now, returning a basic response
        return ResponseEntity.ok(Map.of(
            "valid", true,
            "message", "Token validation endpoint - implement full validation logic"
        ));
    }

    /**
     * Revoke a downscoped token
     */
    @PostMapping("/revoke")
    public ResponseEntity<Map<String, String>> revokeDownscopedToken(
            @RequestBody Map<String, String> request) {
        
        String token = request.get("token");
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Token is required"));
        }

        // This would integrate with Keycloak's token revocation endpoint
        // For now, returning a basic response
        return ResponseEntity.ok(Map.of(
            "message", "Token revocation endpoint - implement full revocation logic"
        ));
    }
}
