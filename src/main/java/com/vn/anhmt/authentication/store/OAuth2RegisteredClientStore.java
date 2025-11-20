package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.configuration.RedisConfiguration;
import com.vn.anhmt.authentication.repository.OAuth2RegisteredClientJpaRepository;
import com.vn.anhmt.authentication.store.mapper.OAuth2RegisteredClientStoreMapper;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class OAuth2RegisteredClientStore implements RegisteredClientRepository {

    private final OAuth2RegisteredClientJpaRepository oauth2RegisteredClientJpaRepository;
    private final RedisCacheManager redisCacheManager;

    @Transactional
    @Override
    public void save(RegisteredClient registeredClient) {
        final var toEntity = OAuth2RegisteredClientStoreMapper.toEntity(registeredClient);
        final var saved = oauth2RegisteredClientJpaRepository.save(toEntity);

        Optional.ofNullable(redisCacheManager.getCache(RedisConfiguration.CLIENTS_CACHE_KEY))
                .ifPresentOrElse(
                        cache -> cache.put(saved.getId(), saved), () -> new RuntimeException("Cache not found"));
    }

    @Cacheable(value = RedisConfiguration.CLIENTS_CACHE_KEY, key = "#id")
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
