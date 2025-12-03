package com.asfaw.keycloak.controller;

import com.asfaw.keycloak.dto.UserRequest;
import com.asfaw.keycloak.service.UserManagementService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class UserAdminController {

    private final UserManagementService userManagementService;

    @GetMapping
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userManagementService.getAllUsers());
    }

    @GetMapping("/search")
    public ResponseEntity<?> getUserByEmail(@RequestParam String email) {
        return ResponseEntity.ok(userManagementService.getUserByEmail(email));
    }

    @GetMapping("/{userId}")
    public ResponseEntity<?> getUserById(@PathVariable String userId) {
        return ResponseEntity.ok(userManagementService.getUserById(userId));
    }

    @PostMapping
    public ResponseEntity<?> createUser(@RequestBody UserRequest userRequest) {
        return userManagementService.createUser(userRequest);
    }

    @PutMapping("/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @RequestBody UserRequest userRequest) {
        return userManagementService.updateUser(userId, userRequest);
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        return userManagementService.deleteUser(userId);
    }

    @PostMapping("/{userId}/reset-password")
    public ResponseEntity<?> resetPassword(@PathVariable String userId, @RequestBody String newPassword) {
        return userManagementService.resetPassword(userId, newPassword);
    }
}