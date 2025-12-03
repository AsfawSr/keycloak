package com.asfaw.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class UserRequest {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Boolean enabled = true;
    private Boolean emailVerified = false;
    private List<Credential> credentials;
    private Map<String, List<String>> attributes;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Credential {
        private String type = "password";
        private String value;
        private Boolean temporary = false;
    }
}