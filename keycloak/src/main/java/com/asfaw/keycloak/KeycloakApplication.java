package com.asfaw.keycloak;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class KeycloakApplication {
    public static void main(String[] args) {
        SpringApplication.run(KeycloakApplication.class, args);
    }
}