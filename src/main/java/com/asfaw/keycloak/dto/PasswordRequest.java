package com.asfaw.keycloak.dto;

import lombok.Data;

@Data
public class PasswordRequest {
    private String type = "password";
    private String value;
    private Boolean temporary = false;
}