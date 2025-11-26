package com.vn.anhmt.authentication.service;

import com.vn.anhmt.authentication.domain.User;
import com.vn.anhmt.authentication.repository.UserRepository;
import com.vn.anhmt.authentication.store.UserStore;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserStore userStore;
    private final UserRepository userRepository;

    public List<User> getAllUsers() {
        return userRepository.findAll().stream()
                .map(userEntity -> User.builder()
                        .id(userEntity.getId())
                        .username(userEntity.getUsername())
                        .password(userEntity.getPassword())
                        .build())
                .collect(Collectors.toList());
    }
}
