package com.vn.anhmt.authentication.configuration.database;

import com.vn.anhmt.authentication.entity.UserEntity;
import com.vn.anhmt.authentication.repository.UserRepository;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class InitUserData implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        initUser();
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
}
