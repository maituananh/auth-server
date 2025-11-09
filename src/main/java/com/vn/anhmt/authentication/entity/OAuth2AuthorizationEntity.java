package com.vn.anhmt.authentication.entity;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.*;

@Table(name = "oauth2_authorization")
@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2AuthorizationEntity {

    @Id
    private String id;

    @Column(name = "registered_client_id", nullable = false)
    private String registeredClientId;

    @Column(name = "principal_name", nullable = false)
    private String principalName;

    @Column(name = "authorization_grant_type", nullable = false)
    private String authorizationGrantType;

    @Column(name = "authorized_scopes", length = 1000)
    private String authorizedScopes;

    @Column(name = "attributes", columnDefinition = "text")
    private String attributes;

    @Column(name = "state", length = 500)
    private String state;

    @Column(name = "authorization_code_value", columnDefinition = "text")
    private String authorizationCodeValue;

    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;

    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;

    @Column(name = "authorization_code_metadata", columnDefinition = "text")
    private String authorizationCodeMetadata;

    @Column(name = "access_token_value", columnDefinition = "text")
    private String accessTokenValue;

    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;

    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;

    @Column(name = "access_token_metadata", columnDefinition = "text")
    private String accessTokenMetadata;

    @Column(name = "access_token_type", length = 100)
    private String accessTokenType;

    @Column(name = "access_token_scopes", length = 1000)
    private String accessTokenScopes;

    @Column(name = "refresh_token_value", columnDefinition = "text")
    private String refreshTokenValue;

    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;

    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;

    @Column(name = "refresh_token_metadata", columnDefinition = "text")
    private String refreshTokenMetadata;

    @Column(name = "oidc_id_token_value", columnDefinition = "text")
    private String oidcIdTokenValue;

    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;

    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;

    @Column(name = "oidc_id_token_metadata", columnDefinition = "text")
    private String oidcIdTokenMetadata;

    @Column(name = "oidc_id_token_claims", columnDefinition = "text")
    private String oidcIdTokenClaims;

    @Column(name = "user_code_value", columnDefinition = "text")
    private String userCodeValue;

    @Column(name = "user_code_issued_at")
    private Instant userCodeIssuedAt;

    @Column(name = "user_code_expires_at")
    private Instant userCodeExpiresAt;

    @Column(name = "user_code_metadata", columnDefinition = "text")
    private String userCodeMetadata;

    @Column(name = "device_code_value", columnDefinition = "text")
    private String deviceCodeValue;

    @Column(name = "device_code_issued_at")
    private Instant deviceCodeIssuedAt;

    @Column(name = "device_code_expires_at")
    private Instant deviceCodeExpiresAt;

    @Column(name = "device_code_metadata", columnDefinition = "text")
    private String deviceCodeMetadata;
}
