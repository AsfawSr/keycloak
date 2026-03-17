package com.asfaw.keycloak.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenDownscopeRequest {
    private String originalToken;
    private String targetService; // Target microservice name
    private List<String> requiredScopes; // Specific scopes needed
    private List<String> requiredRoles; // Specific roles needed
    private Integer expiresIn; // Custom expiration (optional)
    private String audience; // Target audience (optional)
}
