package com.asfaw.keycloak.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Public OK";
    }

    @GetMapping("/secure/hello")
    public String secureHello() {
        return "Secure OK - You are authenticated";
    }

    @GetMapping("/user/hello")
    public String userHello() {
        return "User Hello - You have USER role";
    }

    @GetMapping("/admin/hello")
    public String adminHello() {
        return "Admin Hello - You have ADMIN role";
    }
}