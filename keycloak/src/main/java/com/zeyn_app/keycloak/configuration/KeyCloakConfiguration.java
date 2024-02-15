package com.zeyn_app.keycloak.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "jwt.auth.converter")
public class KeyCloakConfiguration {
    private String resourceId;
    private String principleAttribute;
}

