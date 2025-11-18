package com.vn.anhmt.authentication.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
import lombok.*;

@Table(name = "oauth2_registered_client")
@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Oauth2RegisteredClientEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false)
    private String clientId;

    @Column(name = "client_secret")
    private String clientSecret;

    @Column(name = "client_name")
    private String clientName;

    @Column(name = "client_authentication_methods")
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types")
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris")
    private String redirectUris;

    @Column(name = "scopes")
    private String scopes;

    @Column(name = "client_id_issued_at")
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret_expires_at")
    private Instant clientSecretExpiresAt;

    @Column(name = "token_settings")
    private String tokenSettings;

    @Column(name = "client_settings")
    private String clientSettings;

    @Column(name = "post_logout_redirect_uris")
    private String postLogoutRedirectUris;
}
