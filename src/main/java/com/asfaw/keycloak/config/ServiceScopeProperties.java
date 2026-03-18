package com.asfaw.keycloak.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Data
@Component
@ConfigurationProperties(prefix = "app.keycloak.services")
public class ServiceScopeProperties {

    /**
     * Map of service name -> allowed scopes.
     * e.g. app.keycloak.services.scopes.order-service=read:orders,write:orders
     */
    private Map<String, List<String>> scopes = Collections.emptyMap();

    /**
     * Map of service name -> allowed roles.
     * e.g. app.keycloak.services.roles.order-service=ORDER_USER,ORDER_ADMIN
     */
    private Map<String, List<String>> roles = Collections.emptyMap();
}
