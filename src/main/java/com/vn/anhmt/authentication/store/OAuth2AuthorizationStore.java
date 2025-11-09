package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationEntity;
import com.vn.anhmt.authentication.repository.OAuth2AuthorizationJpaRepository;
import com.vn.anhmt.authentication.store.mapper.OAuth2AuthorizationStoreMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationStore implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationJpaRepository authorizationRepository;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = OAuth2AuthorizationStoreMapper.toEntity(authorization);
        authorizationRepository.save(entity);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        authorizationRepository.deleteById(authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return authorizationRepository.findById(id).map(this::toObject).orElse(null);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        OAuth2AuthorizationEntity entity = null;

        if (tokenType == null) {
            entity = authorizationRepository
                    .findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValueOrOidcIdTokenValueOrUserCodeValueOrDeviceCodeValue(
                            token)
                    .orElse(null);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByState(token).orElse(null);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            entity = authorizationRepository.findByAuthorizationCodeValue(token).orElse(null);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            entity = authorizationRepository.findByAccessTokenValue(token).orElse(null);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            entity = authorizationRepository.findByRefreshTokenValue(token).orElse(null);
        } else if (new OAuth2TokenType("id_token").equals(tokenType)) {
            entity = authorizationRepository.findByOidcIdTokenValue(token).orElse(null);
        } else if (new OAuth2TokenType("user_code").equals(tokenType)) {
            entity = authorizationRepository.findByUserCodeValue(token).orElse(null);
        } else if (new OAuth2TokenType("device_code").equals(tokenType)) {
            entity = authorizationRepository.findByDeviceCodeValue(token).orElse(null);
        }

        return entity != null ? toObject(entity) : null;
    }

    private OAuth2Authorization toObject(OAuth2AuthorizationEntity entity) {
        var registeredClient = registeredClientRepository.findById(entity.getRegisteredClientId());
        if (registeredClient == null) {
            throw new IllegalStateException("Registered client not found: " + entity.getRegisteredClientId());
        }
        return OAuth2AuthorizationStoreMapper.toObject(entity, registeredClient);
    }
}
