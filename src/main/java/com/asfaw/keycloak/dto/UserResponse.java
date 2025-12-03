package com.asfaw.keycloak.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class UserResponse {
    private String id;
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private Boolean enabled;
    @JsonProperty("emailVerified")
    private Boolean emailVerified;
    private Long createdTimestamp;
    private Map<String, List<String>> attributes;
    private List<Credential> credentials;

    @Data
    public static class Credential {
        private String type;
        private String value;
        private Boolean temporary;
    }
}