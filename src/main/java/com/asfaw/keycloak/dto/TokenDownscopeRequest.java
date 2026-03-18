package com.asfaw.keycloak.dto;

import jakarta.validation.constraints.NotBlank;
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

    @NotBlank(message = "targetService must not be blank")
    private String targetService;

    private List<String> requiredScopes;
    private List<String> requiredRoles;
    private Integer expiresIn;
    private String audience;
}
