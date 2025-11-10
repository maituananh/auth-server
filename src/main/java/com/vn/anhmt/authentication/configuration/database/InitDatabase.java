package com.vn.anhmt.authentication.configuration.database;

import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;

import com.vn.anhmt.authentication.entity.UserEntity;
import com.vn.anhmt.authentication.repository.OAuth2RegisteredClientJpaRepository;
import com.vn.anhmt.authentication.repository.UserRepository;
import com.vn.anhmt.authentication.store.mapper.OAuth2RegisteredClientStoreMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class InitDatabase implements CommandLineRunner {

    private final UserRepository userRepository;
    private final OAuth2RegisteredClientJpaRepository oauth2RegisteredClientJpaRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        initUser();
        initRegisteredClient();
        initRegisteredClientPKCE();
    }

    private void initUser() {
        final var user = userRepository.findByUsername("admin");

        if (user.isEmpty()) {
            userRepository.save(UserEntity.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("admin"))
                    .createdAt(Instant.now())
                    .updatedAt(Instant.now())
                    .build());
        }
    }

    private void initRegisteredClient() {
        final var registeredClient = oauth2RegisteredClientJpaRepository.findByClientId("client");

        if (registeredClient.isPresent()) {
            return;
        }

        RegisteredClient registeredClient1 = RegisteredClient.withId(String.valueOf(UUID.randomUUID()))
                .clientId("client")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientName("default")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauthdebugger.com/debug")
                .postLogoutRedirectUri("https://oauthdebugger.com/debug")
                .scope("openid")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofHours(2))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(false)
                        .build())
                .clientIdIssuedAt(Instant.now())
                .build();

        oauth2RegisteredClientJpaRepository.save(OAuth2RegisteredClientStoreMapper.toEntity(registeredClient1));
    }

    private void initRegisteredClientPKCE() {
        final var registeredClient = oauth2RegisteredClientJpaRepository.findByClientId("client-pkce");

        if (registeredClient.isPresent()) {
            return;
        }

        RegisteredClient registeredClient1 = RegisteredClient.withId(String.valueOf(UUID.randomUUID()))
                .clientId("client-pkce")
                .clientSecret(passwordEncoder.encode("secret"))
                .clientName("default-pkce")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://oauthdebugger.com/debug")
                .postLogoutRedirectUri("https://oauthdebugger.com/debug")
                .scope(OPENID)
                .scope(EMAIL)
                .scope(PROFILE)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofHours(2))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .clientIdIssuedAt(Instant.now())
                .build();

        oauth2RegisteredClientJpaRepository.save(OAuth2RegisteredClientStoreMapper.toEntity(registeredClient1));
    }
}
