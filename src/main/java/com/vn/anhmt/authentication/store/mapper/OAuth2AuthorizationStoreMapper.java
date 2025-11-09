package com.vn.anhmt.authentication.store.mapper;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationEntity;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuth2AuthorizationStoreMapper {

    public static OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setAuthorizationGrantType(
                authorization.getAuthorizationGrantType().getValue());
        entity.setAuthorizedScopes(StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","));
        entity.setAttributes(OAuth2CommonMapper.writeMap(authorization.getAttributes()));
        entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        setTokenValues(
                entity,
                authorizationCode,
                entity::setAuthorizationCodeValue,
                entity::setAuthorizationCodeIssuedAt,
                entity::setAuthorizationCodeExpiresAt,
                entity::setAuthorizationCodeMetadata);

        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getToken(OAuth2AccessToken.class);
        setTokenValues(
                entity,
                accessToken,
                entity::setAccessTokenValue,
                entity::setAccessTokenIssuedAt,
                entity::setAccessTokenExpiresAt,
                entity::setAccessTokenMetadata);
        if (accessToken != null && accessToken.getToken().getTokenValue() != null) {
            entity.setAccessTokenType(accessToken.getToken().getTokenType().getValue());
            entity.setAccessTokenScopes(StringUtils.collectionToDelimitedString(
                    accessToken.getToken().getScopes(), ","));
        }

        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getToken(OAuth2RefreshToken.class);
        setTokenValues(
                entity,
                refreshToken,
                entity::setRefreshTokenValue,
                entity::setRefreshTokenIssuedAt,
                entity::setRefreshTokenExpiresAt,
                entity::setRefreshTokenMetadata);

        OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
        setTokenValues(
                entity,
                oidcIdToken,
                entity::setOidcIdTokenValue,
                entity::setOidcIdTokenIssuedAt,
                entity::setOidcIdTokenExpiresAt,
                entity::setOidcIdTokenMetadata);
        if (oidcIdToken != null) {
            entity.setOidcIdTokenClaims(OAuth2CommonMapper.writeMap(oidcIdToken.getClaims()));
        }

        return entity;
    }

    public static OAuth2Authorization toObject(OAuth2AuthorizationEntity entity, RegisteredClient registeredClient) {
        OAuth2Authorization.Builder builder = OAuth2Authorization.withRegisteredClient(registeredClient);
        builder.id(entity.getId());
        builder.principalName(entity.getPrincipalName());
        builder.authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()));
        builder.authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()));
        builder.attributes(attributes -> attributes.putAll(OAuth2CommonMapper.parseMap(entity.getAttributes())));

        if (entity.getState() != null) {
            builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
        }

        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt());
            builder.token(
                    authorizationCode,
                    metadata -> metadata.putAll(OAuth2CommonMapper.parseMap(entity.getAuthorizationCodeMetadata())));
        }

        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
            builder.token(
                    accessToken,
                    metadata -> metadata.putAll(OAuth2CommonMapper.parseMap(entity.getAccessTokenMetadata())));
        }

        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(), entity.getRefreshTokenIssuedAt(), entity.getRefreshTokenExpiresAt());
            builder.token(
                    refreshToken,
                    metadata -> metadata.putAll(OAuth2CommonMapper.parseMap(entity.getRefreshTokenMetadata())));
        }

        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    OAuth2CommonMapper.parseMap(entity.getOidcIdTokenClaims()));
            builder.token(
                    idToken, metadata -> metadata.putAll(OAuth2CommonMapper.parseMap(entity.getOidcIdTokenMetadata())));
        }

        return builder.build();
    }

    private static void setTokenValues(
            OAuth2AuthorizationEntity entity,
            OAuth2Authorization.Token<?> token,
            java.util.function.Consumer<String> tokenValueConsumer,
            java.util.function.Consumer<java.time.Instant> issuedAtConsumer,
            java.util.function.Consumer<java.time.Instant> expiresAtConsumer,
            java.util.function.Consumer<String> metadataConsumer) {
        if (token != null) {
            OAuth2Token oAuth2Token = token.getToken();
            tokenValueConsumer.accept(oAuth2Token.getTokenValue());
            issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
            expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
            metadataConsumer.accept(OAuth2CommonMapper.writeMap(token.getMetadata()));
        }
    }
}
