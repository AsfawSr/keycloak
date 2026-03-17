package com.asfaw.keycloak.controller;

import com.asfaw.keycloak.dto.TokenDownscopeRequest;
import com.asfaw.keycloak.dto.TokenDownscopeResponse;
import com.asfaw.keycloak.service.TokenDownscopingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/microservices")
@RequiredArgsConstructor
@Slf4j
public class MicroserviceExampleController {

    private final TokenDownscopingService tokenDownscopingService;

    /**
     * Example: Get downscoped token for Order Service
     */
    @PostMapping("/order-service/token")
    public ResponseEntity<TokenDownscopeResponse> getOrderServiceToken(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody(required = false) Map<String, Object> customRequest) {
        
        TokenDownscopeRequest request = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("order-service")
                .requiredScopes(Arrays.asList("read:orders", "write:orders"))
                .requiredRoles(Arrays.asList("ORDER_USER"))
                .audience("order-service")
                .expiresIn(3600) // 1 hour
                .build();

        TokenDownscopeResponse response = tokenDownscopingService.downscopeToken(request);
        
        return ResponseEntity.ok()
                .header("X-Downscoped-Token", response.getDownscopedToken())
                .header("X-Target-Service", response.getTargetService())
                .body(response);
    }

    /**
     * Example: Get downscoped token for Payment Service with minimal privileges
     */
    @PostMapping("/payment-service/token")
    public ResponseEntity<TokenDownscopeResponse> getPaymentServiceToken(
            @AuthenticationPrincipal Jwt jwt) {
        
        TokenDownscopeRequest request = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("payment-service")
                .requiredScopes(Arrays.asList("read:payments")) // Read-only access
                .requiredRoles(Arrays.asList("PAYMENT_USER"))
                .audience("payment-service")
                .expiresIn(1800) // 30 minutes - shorter for sensitive operations
                .build();

        TokenDownscopeResponse response = tokenDownscopingService.downscopeToken(request);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Example: Get downscoped token for Notification Service (very limited)
     */
    @PostMapping("/notification-service/token")
    public ResponseEntity<TokenDownscopeResponse> getNotificationServiceToken(
            @AuthenticationPrincipal Jwt jwt) {
        
        TokenDownscopeRequest request = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("notification-service")
                .requiredScopes(Arrays.asList("send:notifications"))
                .audience("notification-service")
                .expiresIn(900) // 15 minutes - very short for notifications
                .build();

        TokenDownscopeResponse response = tokenDownscopingService.downscopeToken(request);
        
        return ResponseEntity.ok(response);
    }

    /**
     * Example: Simulate calling another microservice with downscoped token
     */
    @PostMapping("/call-order-service")
    public ResponseEntity<Map<String, Object>> callOrderService(
            @AuthenticationPrincipal Jwt jwt,
            @RequestBody Map<String, Object> orderData) {
        
        // Step 1: Get downscoped token for order service
        TokenDownscopeRequest downscopeRequest = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("order-service")
                .requiredScopes(Arrays.asList("write:orders"))
                .requiredRoles(Arrays.asList("ORDER_USER"))
                .audience("order-service")
                .build();

        TokenDownscopeResponse downscopedResponse = tokenDownscopingService.downscopeToken(downscopeRequest);
        
        // Step 2: Simulate calling the order service with downscoped token
        // In a real scenario, you would make an HTTP call to the order service
        log.info("Calling order service with downscoped token for user: {}", jwt.getSubject());
        log.info("Downscoped token scopes: {}", downscopedResponse.getGrantedScopes());
        log.info("Downscoped token audience: {}", downscopedResponse.getAudience());
        
        return ResponseEntity.ok(Map.of(
            "message", "Order service called successfully with downscoped token",
            "orderId", "ORD-" + System.currentTimeMillis(),
            "userId", jwt.getSubject(),
            "tokenInfo", Map.of(
                "targetService", downscopedResponse.getTargetService(),
                "audience", downscopedResponse.getAudience(),
                "scopes", downscopedResponse.getGrantedScopes(),
                "expiresIn", downscopedResponse.getExpiresIn()
            )
        ));
    }

    /**
     * Example: Get tokens for multiple services (for complex workflows)
     */
    @PostMapping("/workflow-tokens")
    public ResponseEntity<Map<String, TokenDownscopeResponse>> getWorkflowTokens(
            @AuthenticationPrincipal Jwt jwt) {
        
        // Get tokens for multiple services needed in a workflow
        TokenDownscopeRequest orderRequest = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("order-service")
                .requiredScopes(Arrays.asList("read:orders", "write:orders"))
                .build();

        TokenDownscopeRequest paymentRequest = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("payment-service")
                .requiredScopes(Arrays.asList("read:payments", "write:payments"))
                .build();

        TokenDownscopeRequest notificationRequest = TokenDownscopeRequest.builder()
                .originalToken(jwt.getTokenValue())
                .targetService("notification-service")
                .requiredScopes(Arrays.asList("send:notifications"))
                .build();

        TokenDownscopeResponse orderToken = tokenDownscopingService.downscopeToken(orderRequest);
        TokenDownscopeResponse paymentToken = tokenDownscopingService.downscopeToken(paymentRequest);
        TokenDownscopeResponse notificationToken = tokenDownscopingService.downscopeToken(notificationRequest);

        return ResponseEntity.ok(Map.of(
            "orderService", orderToken,
            "paymentService", paymentToken,
            "notificationService", notificationToken
        ));
    }

    /**
     * Example: Show available services and their capabilities
     */
    @GetMapping("/services")
    public ResponseEntity<Map<String, Object>> getAvailableServices() {
        return ResponseEntity.ok(Map.of(
            "services", Map.of(
                "order-service", Map.of(
                    "scopes", tokenDownscopingService.getServiceScopes("order-service"),
                    "roles", tokenDownscopingService.getServiceRoles("order-service"),
                    "description", "Order management and processing"
                ),
                "payment-service", Map.of(
                    "scopes", tokenDownscopingService.getServiceScopes("payment-service"),
                    "roles", tokenDownscopingService.getServiceRoles("payment-service"),
                    "description", "Payment processing and transactions"
                ),
                "user-service", Map.of(
                    "scopes", tokenDownscopingService.getServiceScopes("user-service"),
                    "roles", tokenDownscopingService.getServiceRoles("user-service"),
                    "description", "User profile and management"
                ),
                "inventory-service", Map.of(
                    "scopes", tokenDownscopingService.getServiceScopes("inventory-service"),
                    "roles", tokenDownscopingService.getServiceRoles("inventory-service"),
                    "description", "Inventory and stock management"
                ),
                "notification-service", Map.of(
                    "scopes", tokenDownscopingService.getServiceScopes("notification-service"),
                    "roles", tokenDownscopingService.getServiceRoles("notification-service"),
                    "description", "Notifications and alerts"
                )
            )
        ));
    }
}
