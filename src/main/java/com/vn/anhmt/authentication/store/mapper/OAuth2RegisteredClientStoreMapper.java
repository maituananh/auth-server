package com.vn.anhmt.authentication.store.mapper;

import com.vn.anhmt.authentication.entity.Oauth2RegisteredClientEntity;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2RegisteredClientStoreMapper {

    public static Oauth2RegisteredClientEntity toEntity(RegisteredClient registeredClient) {
        List<String> clientAuthenticationMethods = new ArrayList<>(
                registeredClient.getClientAuthenticationMethods().size());
        registeredClient
                .getClientAuthenticationMethods()
                .forEach(clientAuthenticationMethod ->
                        clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

        List<String> authorizationGrantTypes =
                new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
        registeredClient
                .getAuthorizationGrantTypes()
                .forEach(authorizationGrantType -> authorizationGrantTypes.add(authorizationGrantType.getValue()));

        Oauth2RegisteredClientEntity entity = new Oauth2RegisteredClientEntity();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientAuthenticationMethods(
                StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
        entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
        entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(
                StringUtils.collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()));
        entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
        entity.setClientSettings(
                OAuth2CommonMapper.writeMap(registeredClient.getClientSettings().getSettings()));
        entity.setTokenSettings(
                OAuth2CommonMapper.writeMap(registeredClient.getTokenSettings().getSettings()));

        return entity;
    }

    public static RegisteredClient toRegisteredClient(Oauth2RegisteredClientEntity client) {
        Set<String> clientAuthenticationMethods =
                StringUtils.commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = StringUtils.commaDelimitedListToSet(client.getRedirectUris());
        Set<String> postLogoutRedirectUris = StringUtils.commaDelimitedListToSet(client.getPostLogoutRedirectUris());
        Set<String> clientScopes = StringUtils.commaDelimitedListToSet(client.getScopes());

        RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(authenticationMethods ->
                        clientAuthenticationMethods.forEach(authenticationMethod -> authenticationMethods.add(
                                OAuth2CommonMapper.resolveClientAuthenticationMethod(authenticationMethod))))
                .authorizationGrantTypes(grantTypes -> authorizationGrantTypes.forEach(
                        grantType -> grantTypes.add(OAuth2CommonMapper.resolveAuthorizationGrantType(grantType))))
                .redirectUris(uris -> uris.addAll(redirectUris))
                .postLogoutRedirectUris(uris -> uris.addAll(postLogoutRedirectUris))
                .scopes(scopes -> scopes.addAll(clientScopes));

        Map<String, Object> clientSettingsMap = OAuth2CommonMapper.parseMap(client.getClientSettings());
        builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

        Map<String, Object> tokenSettingsMap = OAuth2CommonMapper.parseMap(client.getTokenSettings());
        builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

        return builder.build();
    }
}
