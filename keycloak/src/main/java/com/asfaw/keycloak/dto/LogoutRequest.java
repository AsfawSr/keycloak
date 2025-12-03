package com.asfaw.keycloak.dto;


import lombok.Data;

@Data
public class LogoutRequest {
    private String refreshToken;
}
