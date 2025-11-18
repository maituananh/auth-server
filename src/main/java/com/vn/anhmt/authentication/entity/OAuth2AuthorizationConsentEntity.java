package com.vn.anhmt.authentication.entity;

import jakarta.persistence.*;
import java.io.Serializable;
import java.util.UUID;
import lombok.*;

@Table(name = "oauth2_authorization_consent")
@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@IdClass(OAuth2AuthorizationConsentEntity.AuthorizationConsentId.class)
public class OAuth2AuthorizationConsentEntity {

    @Id
    @Column(name = "registered_client_id", nullable = false)
    private UUID registeredClientId;

    @Id
    @Column(name = "principal_name", nullable = false)
    private String principalName;

    @Column(name = "authorities", nullable = false, length = 1000)
    private String authorities;

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthorizationConsentId implements Serializable {
        private String registeredClientId;
        private String principalName;
    }
}
