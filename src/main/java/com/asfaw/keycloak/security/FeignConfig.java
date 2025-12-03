package com.asfaw.keycloak.security;


import feign.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FeignConfig {

    @Bean
    Logger.Level feignLoggerLevel() {
        return Logger.Level.FULL;
    }

    @Bean
    public feign.codec.ErrorDecoder errorDecoder() {
        return new feign.codec.ErrorDecoder.Default();
    }
}
