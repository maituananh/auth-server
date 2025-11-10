package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.entity.OAuth2AuthorizationConsentEntity;
import com.vn.anhmt.authentication.repository.OAuth2AuthorizationConsentJpaRepository;
import com.vn.anhmt.authentication.store.mapper.OAuth2AuthorizationConsentStoreMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2AuthorizationConsentStore implements OAuth2AuthorizationConsentService {

    private final OAuth2AuthorizationConsentJpaRepository authorizationConsentRepository;
    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        OAuth2AuthorizationConsentEntity entity = OAuth2AuthorizationConsentStoreMapper.toEntity(authorizationConsent);
        authorizationConsentRepository.save(entity);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        authorizationConsentRepository.deleteByRegisteredClientIdAndPrincipalName(
                authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        return authorizationConsentRepository
                .findByRegisteredClientIdAndPrincipalName(registeredClientId, principalName)
                .map(entity -> {
                    RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);
                    if (registeredClient == null) {
                        throw new IllegalStateException("Registered client not found: " + registeredClientId);
                    }
                    return OAuth2AuthorizationConsentStoreMapper.toObject(entity);
                })
                .orElse(null);
    }
}
