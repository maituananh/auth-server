package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.repository.UserRepository;
import com.vn.anhmt.authentication.store.mapper.UserStoreMapper;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserStore {

    private final UserRepository userRepository;

    public void findById(final UUID id) {
        userRepository.findById(id);
    }

    public Optional<User> findByUsername(final String username) {
        return userRepository
                .findByUsername(username)
                .map(UserStoreMapper::toUser)
                .orElse(null);
    }
}
