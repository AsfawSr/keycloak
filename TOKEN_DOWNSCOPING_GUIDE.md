# Token Downscoping Implementation Guide

## Overview

This implementation provides **token downscoping** functionality for microservices architecture. Token downscoping is a security pattern that creates limited-scope tokens from a full-privileged token, reducing the attack surface when tokens are intercepted or compromised.

## Why Token Downscoping?

### Security Benefits
- **Principle of Least Privilege**: Each microservice receives only the permissions it needs
- **Reduced Blast Radius**: If a downscoped token is compromised, damage is limited to specific services
- **Shorter Lifetimes**: Downscoped tokens can have shorter expiration times
- **Audience Restriction**: Tokens are restricted to specific microservices
- **Scope Limitation**: Tokens contain only necessary scopes/permissions

### Use Cases
- **Microservices Communication**: Secure service-to-service calls
- **Third-party Integrations**: Grant limited access to external partners
- **Client Applications**: Provide tokens with specific permissions for different features
- **API Gateway**: Downscope tokens before routing to backend services

## Architecture

```
┌─────────────────┐    Original Token     ┌──────────────────┐
│   Client App    │ ────────────────────→ │  Auth Service    │
└─────────────────┘                      └──────────────────┘
                                                 │
                                                 │ Downscope Request
                                                 ▼
                                        ┌──────────────────┐
                                        │  Downscoping     │
                                        │  Service         │
                                        └──────────────────┘
                                                 │
                                                 │ Downscoped Token
                                                 ▼
┌─────────────────┐    Downscoped Token   ┌──────────────────┐
│ Microservice A  │ ◀──────────────────── │  Auth Service    │
└─────────────────┘                      └──────────────────┘
```

## Implementation Components

### 1. TokenDownscopingService
Core service that handles token exchange with Keycloak using OAuth 2.0 Token Exchange.

### 2. TokenDownscopeRequest/Response
DTOs for downscoping requests and responses.

### 3. TokenDownscopingController
REST endpoints for token downscoping operations.

### 4. MicroserviceExampleController
Examples showing how to use downscoping in real scenarios.

## Configuration

### Application Properties
```properties
# TOKEN DOWNSCOPING
app.keycloak.downscope.enabled=true
app.keycloak.downscope.default-expiration=3600
app.keycloak.downscope.max-expiration=7200
app.keycloak.downscope.audience-prefix=microservice-
```

### Keycloak Setup
Ensure your Keycloak realm supports token exchange:
1. Go to Realm Settings → Tokens
2. Enable "Token Exchange" feature
3. Configure appropriate client scopes

## API Endpoints

### Downscope Token
```http
POST /api/tokens/downscope
Content-Type: application/json
Authorization: Bearer <original_token>

{
  "originalToken": "<original_jwt>",
  "targetService": "order-service",
  "requiredScopes": ["read:orders", "write:orders"],
  "requiredRoles": ["ORDER_USER"],
  "expiresIn": 3600,
  "audience": "order-service"
}
```

### Get Service Scopes
```http
GET /api/tokens/scopes/{serviceName}
```

### Get Service Roles
```http
GET /api/tokens/roles/{serviceName}
```

## Usage Examples

### 1. Basic Downscoping
```java
// Get downscoped token for order service
TokenDownscopeRequest request = TokenDownscopeRequest.builder()
    .originalToken(originalToken)
    .targetService("order-service")
    .requiredScopes(Arrays.asList("read:orders", "write:orders"))
    .requiredRoles(Arrays.asList("ORDER_USER"))
    .audience("order-service")
    .expiresIn(3600)
    .build();

TokenDownscopeResponse response = tokenDownscopingService.downscopeToken(request);
```

### 2. Microservice Communication
```java
// Service A calling Service B
@PostMapping("/call-order-service")
public ResponseEntity<?> callOrderService(@AuthenticationPrincipal Jwt jwt) {
    // Get downscoped token
    TokenDownscopeRequest request = TokenDownscopeRequest.builder()
        .originalToken(jwt.getTokenValue())
        .targetService("order-service")
        .requiredScopes(Arrays.asList("write:orders"))
        .build();
    
    TokenDownscopeResponse downscoped = tokenDownscopingService.downscopeToken(request);
    
    // Call order service with downscoped token
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(downscoped.getDownscopedToken());
    
    // Make HTTP call to order service...
}
```

### 3. Workflow with Multiple Services
```java
// Complex workflow requiring multiple services
@PostMapping("/process-order")
public ResponseEntity<?> processOrder(@AuthenticationPrincipal Jwt jwt, OrderData order) {
    // Get tokens for all needed services
    TokenDownscopeResponse orderToken = getTokenForService("order-service", jwt);
    TokenDownscopeResponse paymentToken = getTokenForService("payment-service", jwt);
    TokenDownscopeResponse notificationToken = getTokenForService("notification-service", jwt);
    
    // Execute workflow with appropriate tokens
    // 1. Create order with orderToken
    // 2. Process payment with paymentToken
    // 3. Send notification with notificationToken
}
```

## Predefined Services

The implementation includes predefined configurations for common microservices:

| Service | Scopes | Roles | Description |
|---------|--------|-------|-------------|
| order-service | read:orders, write:orders | ORDER_USER, ORDER_ADMIN | Order management |
| payment-service | read:payments, write:payments | PAYMENT_USER, PAYMENT_ADMIN | Payment processing |
| user-service | read:users, write:users | USER_MANAGER | User management |
| inventory-service | read:inventory, write:inventory | - | Inventory management |
| notification-service | send:notifications | - | Notifications |

## Security Best Practices

### 1. Token Lifetime Management
- **Original Token**: Longer lifetime (e.g., 24 hours)
- **Downscoped Tokens**: Shorter lifetime (e.g., 15 minutes to 1 hour)
- **Sensitive Operations**: Very short lifetime (e.g., 5-15 minutes)

### 2. Scope Minimization
- Always request minimum required scopes
- Use read-only scopes when possible
- Avoid admin-level scopes for regular operations

### 3. Audience Restriction
- Always specify target audience
- Use service-specific audiences
- Prevent token replay across services

### 4. Token Validation
- Validate downscoped tokens at service boundaries
- Check audience and scope claims
- Implement proper token revocation

## Testing the Implementation

### 1. Test Authentication
```bash
# Login to get original token
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"password"}'
```

### 2. Test Downscoping
```bash
# Downscope token for order service
curl -X POST http://localhost:8080/api/tokens/downscope \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <original_token>" \
  -d '{
    "targetService": "order-service",
    "requiredScopes": ["read:orders"],
    "expiresIn": 3600
  }'
```

### 3. Test Microservice Communication
```bash
# Get order service token
curl -X POST http://localhost:8080/api/microservices/order-service/token \
  -H "Authorization: Bearer <original_token>"

# Simulate service call
curl -X POST http://localhost:8080/api/microservices/call-order-service \
  -H "Authorization: Bearer <original_token>" \
  -d '{"productId":"prod-123","quantity":2}'
```

## Monitoring and Logging

The implementation includes comprehensive logging:
- Token downscoping requests/responses
- Validation failures
- Service calls with downscoped tokens
- Security events

Monitor these logs for:
- Unusual downscoping patterns
- Failed token validations
- Excessive token requests
- Security violations

## Error Handling

Common error scenarios:
1. **Invalid Original Token**: Token is expired or invalid
2. **Insufficient Permissions**: Original token lacks required scopes
3. **Service Not Found**: Target service not configured
4. **Keycloak Errors**: Token exchange failures
5. **Network Issues**: Communication problems with Keycloak

## Integration with API Gateway

For production use, integrate with API Gateway:

```java
// API Gateway filter example
@Component
public class TokenDownscopingFilter implements Filter {
    
    @Autowired
    private TokenDownscopingService downscopingService;
    
    public void doFilter(ServletRequest request, ServletResponse response, 
                        FilterChain chain) throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String targetService = determineTargetService(httpRequest);
        
        if (requiresDownscoping(targetService)) {
            String downscopedToken = downscopingService.downscopeToken(
                createDownscopeRequest(httpRequest, targetService)
            ).getDownscopedToken();
            
            // Add downscoped token to request headers
            httpRequest = new HttpServletRequestWrapper(httpRequest) {
                @Override
                public String getHeader(String name) {
                    if ("Authorization".equals(name)) {
                        return "Bearer " + downscopedToken;
                    }
                    return super.getHeader(name);
                }
            };
        }
        
        chain.doFilter(httpRequest, response);
    }
}
```

## Conclusion

This token downscoping implementation provides a robust security solution for microservices architecture. It follows OAuth 2.0 best practices and integrates seamlessly with Keycloak's token exchange capabilities.

Key benefits:
- Enhanced security through principle of least privilege
- Reduced attack surface
- Flexible token management
- Easy integration with existing Spring Boot applications
- Comprehensive monitoring and logging

For production deployment, ensure proper Keycloak configuration, implement monitoring, and follow security best practices for token management.
