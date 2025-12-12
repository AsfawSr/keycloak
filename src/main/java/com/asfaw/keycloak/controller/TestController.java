package com.asfaw.keycloak.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.Map;

@RestController
public class TestController {

    @GetMapping("/public/test")
    public ResponseEntity<?> publicTest() {
        return ResponseEntity.ok(Map.of(
                "message", "Public endpoint works!",
                "timestamp", System.currentTimeMillis()
        ));
    }

    @GetMapping("/secure/test")
    public ResponseEntity<?> secureTest(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "message", "Secure endpoint works!",
                "user", jwt.getSubject(),
                "username", jwt.getClaimAsString("preferred_username"),
                "email", jwt.getClaimAsString("email"),
                "roles", jwt.getClaimAsStringList("realm_access")
        ));
    }

    @GetMapping("/admin/test")
    public ResponseEntity<?> adminTest(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "message", "Admin endpoint works!",
                "user", jwt.getSubject(),
                "isAdmin", true
        ));
    }
}