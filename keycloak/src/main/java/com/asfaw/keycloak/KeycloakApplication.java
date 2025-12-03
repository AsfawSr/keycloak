package com.asfaw.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableFeignClients
@RestController
public class KeycloakApplication {
    public static void main(String[] args) {
        SpringApplication.run(KeycloakApplication.class, args);
    }

    @GetMapping("/Public/login")
    public String publicLogin() {
        return "login";
    }
}