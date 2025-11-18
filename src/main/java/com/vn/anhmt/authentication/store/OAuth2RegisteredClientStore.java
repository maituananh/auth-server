package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.repository.OAuth2RegisteredClientJpaRepository;
import com.vn.anhmt.authentication.store.mapper.OAuth2RegisteredClientStoreMapper;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OAuth2RegisteredClientStore implements RegisteredClientRepository {

    private final OAuth2RegisteredClientJpaRepository oauth2RegisteredClientJpaRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        oauth2RegisteredClientJpaRepository.save(OAuth2RegisteredClientStoreMapper.toEntity(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        final var entity = oauth2RegisteredClientJpaRepository
                .findById(UUID.fromString(id))
                .orElseThrow();

        return OAuth2RegisteredClientStoreMapper.toRegisteredClient(entity);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        final var entity =
                oauth2RegisteredClientJpaRepository.findByClientId(clientId).orElseThrow();

        return OAuth2RegisteredClientStoreMapper.toRegisteredClient(entity);
    }
}
