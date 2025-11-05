package com.vn.anhmt.authentication.store;

import com.vn.anhmt.authentication.domain.Token;
import com.vn.anhmt.authentication.repository.TokenRepository;
import com.vn.anhmt.authentication.store.mapper.TokenStoreMapper;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TokenStore {

    private final TokenRepository tokenRepository;

    public void findById(final UUID id) {
        tokenRepository.findById(id);
    }

    public Optional<Token> findByAccessToken(final String accessToken) {
        return tokenRepository
                .findByAccessToken(accessToken)
                .map(TokenStoreMapper::toToken)
                .orElse(null);
    }
}
