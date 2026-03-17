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
public class TokenDownscopeResponse {
    private String downscopedToken;
    private String tokenType;
    private Long expiresIn;
    private List<String> grantedScopes;
    private List<String> grantedRoles;
    private String audience;
    private String targetService;
    private String issuedAt;
}
