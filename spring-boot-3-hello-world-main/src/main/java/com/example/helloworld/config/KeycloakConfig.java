package com.example.helloworld.config;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakConfig {

    @Value("${keycloak.url}")
    private String serverUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.admin-username}")
    private String adminUsername;

    @Value("${keycloak.admin-password}")
    private String adminPassword;

    @Value("${keycloak.client-id}")
    private String clientId;

    @Value("${keycloak.client-secret}")
    private String clientSecret;

    @Bean
    public Keycloak keycloakAdminClient() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)              // http://localhost:8080
                .realm("master")                   // PHẢI là "master" nếu bạn dùng admin
                .grantType(OAuth2Constants.PASSWORD)
                .clientId("admin-cli")             // ❗ Dùng "admin-cli" là tốt nhất khi login bằng user admin
                .username(adminUsername)           // "admin"
                .password(adminPassword)           // "admin"
                .build();
    }
}

