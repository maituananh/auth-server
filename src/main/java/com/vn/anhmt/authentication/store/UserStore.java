package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.configuration.RedisConfiguration;
import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.repository.UserRepository;
import com.vn.anhmt.authentication.store.mapper.UserStoreMapper;
import java.util.Optional;
import java.util.UUID;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserStore {

    private final UserRepository userRepository;

    @Cacheable(value = RedisConfiguration.USERS_CACHE_KEY, key = "#id")
    public Optional<User> findById(@NonNull final UUID id) {
        return userRepository.findById(id).map(UserStoreMapper::toUser);
    }

    public Optional<User> findByUsername(@NonNull final String username) {
        return userRepository.findByUsername(username).map(UserStoreMapper::toUser);
    }
}
